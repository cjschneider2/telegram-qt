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
    case ConnectionApi::StatusConnected:
    case ConnectionApi::StatusReady:
        return true;
    case ConnectionApi::StatusDisconnected:
    case ConnectionApi::StatusConnecting:
    case ConnectionApi::StatusWaitForAuthentication:
        return false;
    }
    Q_UNREACHABLE();
}

bool ConnectionApiPrivate::connectToServer()
{
    QVariantHash errorDetails = getBackendSetupErrorDetails();
    if (!errorDetails.isEmpty()) {
        qCWarning(c_connectionApiLoggingCategory) << "Unable to initiate connection:" << errorDetails;
        return false;
    }

    connectToServer(backend()->settings()->serverConfiguration());
    return true;
}

void ConnectionApiPrivate::disconnectFromServer()
{

}

void ConnectionApiPrivate::connectToServer(const QVector<DcOption> &dcOptions)
{
    if (dcOptions.isEmpty()) {
        qCCritical(c_connectionApiLoggingCategory) << "Unable to connect to server without no any address given";
        return;
    }
    m_serverConfiguration = dcOptions;
    m_nextServerAddressIndex = 0;
    connectToNextServer();
}

void ConnectionApiPrivate::connectToNextServer()
{
    if (m_initialConnection) {
        disconnect(m_initialConnection, &BaseConnection::statusChanged,
                   this, &ConnectionApiPrivate::onInitialConnectionStatusChanged);
        m_initialConnection->deleteLater();
        m_initialConnection = nullptr;
    }

    m_initialConnection = createConnection(m_serverConfiguration.at(m_nextServerAddressIndex));
    connect(m_initialConnection, &BaseConnection::statusChanged, this, &ConnectionApiPrivate::onInitialConnectionStatusChanged);

    m_initialConnection->connectToDc();
    ++m_nextServerAddressIndex;
    if (m_serverConfiguration.count() <= m_nextServerAddressIndex) {
        m_nextServerAddressIndex = 0;
    }
}

void ConnectionApiPrivate::queueConnectToNextServer()
{
    setStatus(ConnectionApi::StatusWaitForReconnection, ConnectionApi::StatusReasonLocal);
    connectToNextServer();
}

Connection *ConnectionApiPrivate::getDefaultConnection()
{
    if (m_mainConnection) {
        return m_mainConnection;
    }
    if (m_initialConnection) {
        return m_initialConnection;
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

/*! \fn ConnectOperation *ConnectionApiPrivate::connectToServer(const QVector<DcOption> &dcOptions)

  The operation succeed on DH-encrypted connection established with any server from \a dcOptions.
  The operation fails in case of incorrect setup or if there is an already active connection operation.
*/
ConnectOperation *ConnectionApiPrivate::connectToServerOld(const QVector<DcOption> &dcOptions)
{
    if (m_initialConnectOperation) {
        if (dcOptions.contains(m_initialConnectOperation->connection()->dcOption())) {
            switch (m_initialConnectOperation->connection()->status()) {
            case BaseConnection::Status::Connecting:
            case BaseConnection::Status::Connected:
            case BaseConnection::Status::HasDhKey:
            case BaseConnection::Status::Signed:
                return m_initialConnectOperation;
            default:
                m_initialConnectOperation->connection()->transport()->disconnectFromHost();
                break;
            }
        }
        m_initialConnectOperation->deleteLater();
        m_initialConnectOperation = nullptr;
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
            this, &ConnectionApiPrivate::onInitialConnectionStatusChanged);

    m_initialConnectOperation = connection->connectToDcOld();
    connect(m_initialConnectOperation, &PendingOperation::finished, this, &ConnectionApiPrivate::onInitialConnectOperationFinished);
    return m_initialConnectOperation;
}

AuthOperation *ConnectionApiPrivate::startAuthentication()
{
    QVariantHash errorDetails = getBackendSetupErrorDetails();
    if (!errorDetails.isEmpty()) {
        return PendingOperation::failOperation<AuthOperation>(errorDetails, this);
    }
    if (status() != ConnectionApi::StatusWaitForAuthentication) {
        return PendingOperation::failOperation<AuthOperation>
                (QStringLiteral("Invalid connection status (expected StatusWaitForAuthentication)"), this);
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
    m_authOperation->startLater();
    return m_authOperation;
}

AuthOperation *ConnectionApiPrivate::checkIn()
{
    QVariantHash errorDetails = getBackendSetupErrorDetails();
    if (!errorDetails.isEmpty()) {
        qCWarning(c_connectionApiLoggingCategory) << "Unable to initiate connection:" << errorDetails;
        return nullptr;
    }

    connectToServerOld(backend()->settings()->serverConfiguration());




//    if (m_authOperation && !m_authOperation->isFinished()) {
//        return PendingOperation::failOperation<AuthOperation>
//                (QStringLiteral("Auth operation is already in progress"), this);
//    }
//    AccountStorage *accountStorage = backend()->accountStorage();
//    if (!accountStorage || !accountStorage->hasMinimalDataSet()) {
//        return PendingOperation::failOperation<AuthOperation>
//                (QStringLiteral("No minimal account data set"), this);
//    }
//    m_authOperation = new AuthOperation(this);
//    AuthOperationPrivate *priv = AuthOperationPrivate::get(m_authOperation);
//    priv->setBackend(backend());
//    priv->setRunMethod(&AuthOperation::checkAuthorization);
//    connect(m_authOperation, &AuthOperation::finished, this, &ConnectionApiPrivate::onAuthFinished);
//    if (m_mainConnection) {
//        m_authOperation->startLater();
//    } else {
//        ConnectOperation *connectionOperation = connectToServer({accountStorage->dcInfo()});
//        connectionOperation->connection()->setAuthKey(accountStorage->authKey());
//        connectionOperation->connection()->rpcLayer()->setSessionData(
//                    accountStorage->sessionId(),
//                    accountStorage->contentRelatedMessagesNumber());
//        m_authOperation->runAfter(connectionOperation);
//    }
//    return m_authOperation;
    return nullptr;
}

QVariantHash ConnectionApiPrivate::getBackendSetupErrorDetails() const
{
    if (!backend()->accountStorage()) {
        return {{PendingOperation::c_text(), QStringLiteral("Account storage is missing")}};
    }
    if (!backend()->dataStorage()) {
        return {{PendingOperation::c_text(), QStringLiteral("Data storage is missing")}};
    }
    Settings *settings = backend()->settings();
    if (!settings) {
        return {{PendingOperation::c_text(), QStringLiteral("Settings object is missing")}};
    }
    if (!settings->isValid()) {
        return {{PendingOperation::c_text(), QStringLiteral("Invalid settings")}};
    }
    return {};
}

/*!
  \fn Connection *ConnectionApiPrivate::createConnection(const DcOption &dcOption)

  The method constructs new Connection ready to connect to the passed server address.
*/
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

/*!
  \fn Connection *ConnectionApiPrivate::ensureConnection(const DcOption &dcOption)

  The method returns new or existing Connection to the passed server address.

  The returned Connection is prepaired to work with /a connectionSpec and can have any status.
*/
Connection *ConnectionApiPrivate::ensureConnection(const ConnectionSpec &connectionSpec)
{
    qCDebug(c_connectionApiLoggingCategory) << Q_FUNC_INFO << connectionSpec.dcId << connectionSpec.flags;
    ConnectionSpec spec = connectionSpec;
    spec.flags |= ConnectionSpec::RequestFlag::Ipv4Only; // Enable only ipv4 for now
    if (!m_connections.contains(connectionSpec)) {
        const DcOption opt = backend()->dataStorage()->serverConfiguration().getOption(spec);
        if (!opt.isValid()) {
            qCWarning(c_connectionApiLoggingCategory) << Q_FUNC_INFO << "Unable to find suitable DC";
            return nullptr;
        }
        m_connections.insert(connectionSpec, createConnection(opt));
    }
    return m_connections.value(connectionSpec);
}

void ConnectionApiPrivate::onInitialConnectOperationFinished(PendingOperation *operation)
{
    disconnect(m_initialConnection, &BaseConnection::statusChanged,
               this, &ConnectionApiPrivate::onInitialConnectionStatusChanged);

}

void ConnectionApiPrivate::onReconnectOperationFinished(PendingOperation *operation)
{
    qWarning() << Q_FUNC_INFO << "reconnect result:" << operation->errorDetails();
    if (operation->isSucceeded()) {
        checkIn();
    }
}

void ConnectionApiPrivate::onInitialConnectionStatusChanged(BaseConnection::Status status,
                                                             BaseConnection::StatusReason reason)
{
    qCDebug(c_connectionApiLoggingCategory) << Q_FUNC_INFO << status << reason;
    switch (status) {
    case BaseConnection::Status::Disconnected:
    case BaseConnection::Status::Disconnecting:
        connectToNextServer();
        break;
    case BaseConnection::Status::Connecting:
        setStatus(ConnectionApi::StatusConnecting, ConnectionApi::StatusReasonNone);
        break;
    case BaseConnection::Status::Connected:
        // Nothing to do; wait for DH
        break;
    case BaseConnection::Status::HasDhKey:
        backend()->getDcConfig();
        setStatus(ConnectionApi::StatusWaitForAuthentication, ConnectionApi::StatusReasonNone);
        break;
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
        setStatus(ConnectionApi::StatusWaitForAuthentication, ConnectionApi::StatusReasonNone);
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
    setStatus(ConnectionApi::StatusWaitForAuthentication, ConnectionApi::StatusReasonRemote);
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
        setStatus(ConnectionApi::StatusConnected, ConnectionApi::StatusReasonNone);
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
        case ConnectionApi::StatusConnected:
        case ConnectionApi::StatusReady:
            setStatus(ConnectionApi::StatusConnecting, ConnectionApi::StatusReasonRemote);
            DcOption wantedOption = m_mainConnection->dcOption();
            m_mainConnection->deleteLater();
            PendingOperation *reconnectOperation = connectToServerOld({wantedOption});
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

/*!
    \class Telegram::Client::ConnectionApi
    \inmodule TelegramQt
    \ingroup Client
*/

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

/*! \fn bool ConnectionApi::connectToServer()

  Establish a connection to a server from Settings

  Returns \c false in case of incorrect setup; otherwise returns \c true.

  \sa disconnectFromServer()
*/
bool ConnectionApi::connectToServer()
{
    Q_D(ConnectionApi);
    return d->connectToServer();
}

/*! \fn void ConnectionApi::disconnectFromServer()
  Establish a connection to a server from Settings

  Return false in case of incorrect setup, returns true otherwise.
*/
void ConnectionApi::disconnectFromServer()
{
    Q_D(ConnectionApi);
    return d->disconnectFromServer();
}

Telegram::Client::AuthOperation *ConnectionApi::startAuthentication()
{
    Q_D(ConnectionApi);
    return d->startAuthentication();
}

/*! \fn AuthOperation *ConnectionApi::checkIn()
  High level API for establishing the main connection needed for the most of RPC calls

  The operation succeed on connection established and server confirmed the session data.
  The typical reasons to fail are:
  \list 1
      \li There is an already active connection
      \li The account storage has no session information
      \li Incorrect setup (e.g. AccountStorage is not set)
      \li Server declined the session data
      \li The session is explicitly revoked from another session
  \endlist

  \note The operation doesn't fail in case of network errors (it keeps trying to connect).

  \sa PendingOperation::errorDetails()
*/
Telegram::PendingOperation *ConnectionApi::checkIn()
{
    Q_D(ConnectionApi);
    return d->checkIn();
}

} // Client namespace

} // Telegram namespace
