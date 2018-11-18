#include "ConnectionApi_p.hpp"

#include "AccountStorage.hpp"
#include "ClientBackend.hpp"
#include "ClientConnection.hpp"
#include "ClientRpcLayer.hpp"
#include "ClientSettings.hpp"
#include "CTelegramTransport.hpp"
#include "CClientTcpTransport.hpp"
#include "DataStorage.hpp"

#include "Operations/ClientAuthOperation_p.hpp"
#include "Operations/ClientPingOperation.hpp"
#include "Operations/ConnectionOperation.hpp"

#include <QLoggingCategory>

Q_LOGGING_CATEGORY(c_connectionApiLoggingCategory, "telegram.client.api.connection", QtWarningMsg)

namespace Telegram {

namespace Client {

ConnectionApiPrivate::ConnectionApiPrivate(ConnectionApi *parent) :
    ClientApiPrivate(parent)
{
}

ConnectionApiPrivate *ConnectionApiPrivate::get(ConnectionApi *parent)
{
    return reinterpret_cast<ConnectionApiPrivate*>(parent->d);
}

bool ConnectionApiPrivate::isSignedIn() const
{
    switch (m_status) {
    case ConnectionApi::StatusAuthenticated:
    case ConnectionApi::StatusReady:
        return true;
    case ConnectionApi::StatusDisconnected:
    case ConnectionApi::StatusConnecting:
    case ConnectionApi::StatusConnected:
    case ConnectionApi::StatusAuthRequired:
        return false;
    }
    Q_UNREACHABLE();
}

Connection *ConnectionApiPrivate::getDefaultConnection()
{
    if (mainConnection()) {
        return mainConnection();
    }

    if (m_connectToServerOperation) {
        return m_connectToServerOperation->connection();
    }
    return nullptr;
}

Connection *ConnectionApiPrivate::mainConnection()
{
    return m_mainConnection;
}

void ConnectionApiPrivate::setMainConnection(Connection *connection)
{
    m_mainConnection = connection;
    connect(m_mainConnection, &BaseConnection::statusChanged, this, &ConnectionApiPrivate::onMainConnectionStatusChanged);
    onMainConnectionStatusChanged(connection->status(), Connection::StatusReason::Local);
}

ConnectOperation *ConnectionApiPrivate::connectToServer(const QVector<DcOption> &dcOptions)
{
    if (m_connectToServerOperation) {
        if (dcOptions.contains(m_connectToServerOperation->connection()->dcOption())) {
            switch (m_connectToServerOperation->connection()->status()) {
            case BaseConnection::Status::Connecting:
            case BaseConnection::Status::Connected:
            case BaseConnection::Status::HasDhKey:
            case BaseConnection::Status::Signed:
                return m_connectToServerOperation;
            default:
                m_connectToServerOperation->connection()->transport()->disconnectFromHost();
                break;
            }
        }
        m_connectToServerOperation->deleteLater();
        m_connectToServerOperation = nullptr;
    }

    if (mainConnection()) {
        if (mainConnection()->status() != Connection::Status::Disconnected) {
            return PendingOperation::failOperation<ConnectOperation>
                    (QStringLiteral("Connection is already in progress"), this);
        } else {
            // TODO!
        }
    }

    if (!backend()->accountStorage()) {
        return PendingOperation::failOperation<ConnectOperation>
                (QStringLiteral("Account storage is missing"), this);
    }
    if (!backend()->dataStorage()) {
        return PendingOperation::failOperation<ConnectOperation>
                (QStringLiteral("Data storage is missing"), this);
    }

    Connection *connection = createConnection(dcOptions.first());
    connect(connection, &BaseConnection::statusChanged,
            this, &ConnectionApiPrivate::onUpcomingConnectionStatusChanged);

    m_connectToServerOperation = connection->connectToDc();
    connect(m_connectToServerOperation, &PendingOperation::finished, this, &ConnectionApiPrivate::onConnectOperationFinished);
    return m_connectToServerOperation;
}

AuthOperation *ConnectionApiPrivate::signIn()
{
    if (isSignedIn()) {
        return PendingOperation::failOperation<AuthOperation>
                (QStringLiteral("Already signed in"), this);
    }
    Settings *settings = backend()->m_settings;
    if (!settings || !settings->isValid()) {
        qCWarning(c_connectionApiLoggingCategory) << "Invalid settings";
        return PendingOperation::failOperation<AuthOperation>
                (QStringLiteral("Invalid settings"), this);
    }
    if (m_authOperation && !m_authOperation->isFinished()) {
        return PendingOperation::failOperation<AuthOperation>
                (QStringLiteral("Auth operation is already in progress"), this);
    }

    m_authOperation = new AuthOperation(this);
    AuthOperationPrivate *priv = AuthOperationPrivate::get(m_authOperation);
    priv->setBackend(backend());
    priv->setRunMethod(&AuthOperation::requestAuthCode);
    connect(m_authOperation, &AuthOperation::finished, this, &ConnectionApiPrivate::onAuthFinished);
    connect(m_authOperation, &AuthOperation::authCodeRequired, this, &ConnectionApiPrivate::onAuthCodeRequired);
    PendingOperation *connectionOperation = connectToServer(settings->serverConfiguration());
    m_authOperation->runAfter(connectionOperation);
    return m_authOperation;
}

AuthOperation *ConnectionApiPrivate::checkIn()
{
    if (m_authOperation && !m_authOperation->isFinished()) {
        return PendingOperation::failOperation<AuthOperation>
                (QStringLiteral("Auth operation is already in progress"), this);
    }
    AccountStorage *accountStorage = backend()->accountStorage();
    if (!accountStorage || !accountStorage->hasMinimalDataSet()) {
        return PendingOperation::failOperation<AuthOperation>
                (QStringLiteral("No minimal account data set"), this);
    }
    m_authOperation = new AuthOperation(this);
    AuthOperationPrivate *priv = AuthOperationPrivate::get(m_authOperation);
    priv->setBackend(backend());
    priv->setRunMethod(&AuthOperation::checkAuthorization);
    connect(m_authOperation, &AuthOperation::finished, this, &ConnectionApiPrivate::onAuthFinished);
    if (m_mainConnection) {
        m_authOperation->startLater();
    } else {
        ConnectOperation *connectionOperation = connectToServer({accountStorage->dcInfo()});
        connectionOperation->connection()->setAuthKey(accountStorage->authKey());
        connectionOperation->connection()->rpcLayer()->setSessionData(
                    accountStorage->sessionId(),
                    accountStorage->contentRelatedMessagesNumber());
        m_authOperation->runAfter(connectionOperation);
    }
    return m_authOperation;
}

Connection *ConnectionApiPrivate::createConnection(const DcOption &dcOption)
{
    Connection *connection = new Connection(this);
    connection->setDcOption(dcOption);
    connection->rpcLayer()->setAppInformation(backend()->m_appInformation);
    connection->rpcLayer()->installUpdatesHandler(backend()->updatesApi());
    connection->setDeltaTime(backend()->accountStorage()->deltaTime());

    Settings *settings = backend()->m_settings;
    connection->setServerRsaKey(settings->serverRsaKey());
    TcpTransport *transport = new TcpTransport(connection);
    transport->setProxy(settings->proxy());

    switch (settings->preferedSessionType()) {
    case Settings::SessionType::None:
        qCWarning(c_connectionApiLoggingCategory) << Q_FUNC_INFO << "Session type is not set. Use fallback.";
        transport->setPreferedSessionType(TcpTransport::Obfuscated);
        break;
    case Settings::SessionType::Abridged:
        transport->setPreferedSessionType(TcpTransport::Abridged);
        break;
    case Settings::SessionType::Obfuscated:
        transport->setPreferedSessionType(TcpTransport::Obfuscated);
        break;
    }
    connection->setTransport(transport);
    return connection;
}

Connection *ConnectionApiPrivate::ensureConnection(const ConnectionSpec &dcSpec)
{
    qCDebug(c_connectionApiLoggingCategory) << Q_FUNC_INFO << dcSpec.dcId << dcSpec.flags;
    ConnectionSpec spec = dcSpec;
    spec.flags |= ConnectionSpec::RequestFlag::Ipv4Only; // Enable only ipv4 for now
    if (!m_connections.contains(dcSpec)) {
        const DcOption opt = backend()->dataStorage()->serverConfiguration().getOption(spec);
        if (!opt.isValid()) {
            qCWarning(c_connectionApiLoggingCategory) << Q_FUNC_INFO << "Unable to find suitable DC";
            return nullptr;
        }
        m_connections.insert(dcSpec, createConnection(opt));
    }
    return m_connections.value(dcSpec);
}

void ConnectionApiPrivate::onConnectOperationFinished(PendingOperation *operation)
{
    disconnect(m_connectToServerOperation->connection(), &BaseConnection::statusChanged,
               this, &ConnectionApiPrivate::onUpcomingConnectionStatusChanged);

    if (operation->isSucceeded()) {
        backend()->getDcConfig();
        return;
    }
    m_connectToServerOperation = nullptr;
    operation->deleteLater();
    setStatus(ConnectionApi::StatusDisconnected, ConnectionApi::StatusReasonNone);
}

void ConnectionApiPrivate::onReconnectOperationFinished(PendingOperation *operation)
{
    qWarning() << Q_FUNC_INFO << "reconnect result:" << operation->errorDetails();
    if (operation->isSucceeded()) {
        checkIn();
    }
}

void ConnectionApiPrivate::onUpcomingConnectionStatusChanged(BaseConnection::Status status,
                                                             BaseConnection::StatusReason reason)
{
    qCDebug(c_connectionApiLoggingCategory) << Q_FUNC_INFO << status << reason;
    switch (status) {
    case BaseConnection::Status::Disconnected:
    case BaseConnection::Status::Disconnecting:
        setStatus(ConnectionApi::StatusDisconnected, ConnectionApi::StatusReasonNone);
        break;
    case BaseConnection::Status::Connecting:
        setStatus(ConnectionApi::StatusConnecting, ConnectionApi::StatusReasonNone);
        break;
    case BaseConnection::Status::Connected:
        setStatus(ConnectionApi::StatusConnected, ConnectionApi::StatusReasonNone);
        break;
    case BaseConnection::Status::HasDhKey:
    case BaseConnection::Status::Signed:
    case BaseConnection::Status::Failed:
        break;
    }
}

void ConnectionApiPrivate::onAuthFinished(PendingOperation *operation)
{
    if (operation != m_authOperation) {
        qCCritical(c_connectionApiLoggingCategory) << Q_FUNC_INFO << "Unexpected auth operation";
        return;
    }
    if (!operation->isSucceeded()) {
        setStatus(ConnectionApi::StatusAuthRequired, ConnectionApi::StatusReasonNone);
        qCDebug(c_connectionApiLoggingCategory) << Q_FUNC_INFO << "TODO?";
        return;
    }
    AuthOperationPrivate *priv = AuthOperationPrivate::get(m_authOperation);
    Connection *conn = priv->m_authenticatedConnection;
    if (conn->status() != Connection::Status::Signed) {
        qCCritical(c_connectionApiLoggingCategory) << Q_FUNC_INFO << "Unexpected connection status" << conn->status();
        return;
    }
    setMainConnection(conn);
}

void ConnectionApiPrivate::onAuthCodeRequired()
{
    setStatus(ConnectionApi::StatusAuthRequired, ConnectionApi::StatusReasonRemote);
}

void ConnectionApiPrivate::onMainConnectionStatusChanged(BaseConnection::Status status, BaseConnection::StatusReason reason)
{
    if (!m_mainConnection) {
        return;
    }

    const bool keepAliveIsWanted = (status == Connection::Status::Signed) || (status == Connection::Status::HasDhKey);
    if (keepAliveIsWanted) {
        if (!m_pingOperation) {
            m_pingOperation = new PingOperation(this);
            m_pingOperation->setSettings(backend()->m_settings);
            m_pingOperation->setRpcLayer(m_mainConnection->rpcLayer());
            connect(m_pingOperation, &PingOperation::pingFailed, this, &ConnectionApiPrivate::onPingFailed);
        }
        m_pingOperation->ensureActive();
    } else {
        if (m_pingOperation) {
            m_pingOperation->ensureInactive();
        }
    }

    switch (status) {
    case Connection::Status::Signed:
    {
        backend()->syncAccountToStorage();
        setStatus(ConnectionApi::StatusAuthenticated, ConnectionApi::StatusReasonNone);
        PendingOperation *syncOperation = backend()->sync();
        connect(syncOperation, &PendingOperation::finished, this, &ConnectionApiPrivate::onSyncFinished);
        syncOperation->startLater();
        break;
    }
    case Connection::Status::Disconnected:
    {
        switch (m_status) {
        case ConnectionApi::StatusDisconnecting:
            setStatus(ConnectionApi::StatusDisconnected, ConnectionApi::StatusReasonLocal);
            break;
        case ConnectionApi::StatusAuthenticated:
        case ConnectionApi::StatusReady:
            setStatus(ConnectionApi::StatusConnecting, ConnectionApi::StatusReasonRemote);
            DcOption wantedOption = m_mainConnection->dcOption();
            m_mainConnection->deleteLater();
            PendingOperation *reconnectOperation = connectToServer({wantedOption});
            connect(reconnectOperation, &PendingOperation::finished,
                    this, &ConnectionApiPrivate::onReconnectOperationFinished);

            //m_connectToServerOperation = m_mainConnection->connectToDc();
            //connect(m_connectToServerOperation, &ConnectOperation::finished,
            //        this, &ConnectionApiPrivate::onReconnectOperationFinished);
            break;
        }
    }
        break;
    default:
        qWarning() << Q_FUNC_INFO << status << reason;
    }
}

void ConnectionApiPrivate::onSyncFinished(PendingOperation *operation)
{
    if (operation->isSucceeded()) {
        setStatus(ConnectionApi::StatusReady, ConnectionApi::StatusReasonLocal);
    } else {
        qCCritical(c_connectionApiLoggingCategory) << Q_FUNC_INFO << "Unexpected sync operation status" << operation->errorDetails();
    }
}

void ConnectionApiPrivate::onPingFailed()
{
    qCWarning(c_connectionApiLoggingCategory) << Q_FUNC_INFO;
}

void ConnectionApiPrivate::setStatus(ConnectionApi::Status status, ConnectionApi::StatusReason reason)
{
    Q_Q(ConnectionApi);
    if (m_status == status) {
        return;
    }
    m_status = status;
    emit q->statusChanged(status, reason);
}

ConnectionApi::ConnectionApi(QObject *parent) :
    ClientApi(parent)
{
    d = new ConnectionApiPrivate(this);
}

bool ConnectionApi::isSignedIn() const
{
    Q_D(const ConnectionApi);
    return d->isSignedIn();
}

ConnectionApi::Status ConnectionApi::status() const
{
    Q_D(const ConnectionApi);
    return d->status();
}

Telegram::Client::AuthOperation *ConnectionApi::signUp()
{
     return signIn();
}

Telegram::Client::AuthOperation *ConnectionApi::signIn()
{
    Q_D(ConnectionApi);
    return d->signIn();
}

AuthOperation *ConnectionApi::checkIn()
{
    Q_D(ConnectionApi);
    return d->checkIn();
}

PendingOperation *ConnectionApi::disconnectFromHost()
{
    return nullptr;
}

} // Client namespace

} // Telegram namespace
