#include "ClientConnection.hpp"

#include "ApiUtils.hpp"
#include "ClientDhLayer.hpp"
#include "ClientRpcLayer.hpp"
#include "CTelegramTransport.hpp"
#include "SendPackageHelper.hpp"
#include "Utils.hpp"
#include "Debug_p.hpp"

#include "PendingRpcOperation.hpp"
#include "Operations/ConnectionOperation.hpp"

#include <QDateTime>
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(c_clientConnectionCategory, "telegram.client.connection", QtWarningMsg)

namespace Telegram {

namespace Client {

class SendPackageHelper : public BaseSendPackageHelper
{
public:
    explicit SendPackageHelper(BaseConnection *connection) :
        BaseSendPackageHelper()
    {
        m_connection = connection;
    }

    quint64 newMessageId(SendMode mode) override
    {
        quint64 ts = Telegram::Utils::formatTimeStamp(QDateTime::currentMSecsSinceEpoch() + deltaTime() * 1000);
        if (mode == SendMode::Client) {
            ts &= ~quint64(3);
        } else {
            qCWarning(c_clientConnectionCategory) << Q_FUNC_INFO << "Invalid mode";
        }
        return m_connection->transport()->getNewMessageId(ts);
    }

    void sendPackage(const QByteArray &package) override
    {
        return m_connection->transport()->sendPackage(package);
    }
};

/*!
    \class Telegram::Client::Connection
    \brief Client-specific connection with DH and RPC layers
    \inmodule TelegramQt
    \ingroup Client
*/
Connection::Connection(QObject *parent) :
    BaseConnection(parent)
{
    m_sendHelper = new SendPackageHelper(this);
    m_dhLayer = new DhLayer(this);
    m_dhLayer->setSendPackageHelper(m_sendHelper);
    connect(m_dhLayer, &BaseDhLayer::stateChanged, this, &Connection::onClientDhStateChanged);
    m_rpcLayer = new RpcLayer(this);
    m_rpcLayer->setSendPackageHelper(m_sendHelper);
}

void Connection::setDcOption(const DcOption &dcOption)
{
    m_dcOption = dcOption;
}

qint32 Connection::deltaTime() const
{
    return m_sendHelper->deltaTime();
}

void Connection::setDeltaTime(const qint32 newDt)
{
    m_sendHelper->setDeltaTime(newDt);
}

Connection *Connection::fromOperation(PendingRpcOperation *operation)
{
    return reinterpret_cast<Telegram::Client::Connection*>(operation->getConnection());
}

RpcLayer *Connection::rpcLayer()
{
    return reinterpret_cast<RpcLayer*>(m_rpcLayer);
}

void Connection::connectToDc()
{
    setStatus(Status::Connecting, StatusReason::Local);
    m_transport->connectToHost(m_dcOption.address, m_dcOption.port);
}

/*!
  \fn ConnectOperation *Connection::connectToDc()

  Initiates connection to DC and returns an Operation object.

  This method establish Transport (TCP/UDP/HTTP) level connection.
  Operation is finished on transport (network) error or on DH layer
  connection established.

  \sa BaseTransport::connectToHost()
*/
ConnectOperation *Connection::connectToDcOld()
{
    if (m_status != Status::Disconnected) {
        const QString text = QStringLiteral("Connection is already in progress");
        return PendingOperation::failOperation<ConnectOperation>(text, this);
    }

#ifdef DEVELOPER_BUILD
    qCDebug(c_clientConnectionCategory) << Q_FUNC_INFO << m_dcOption.id << m_dcOption.address << m_dcOption.port;
#endif

    if (m_transport->state() != QAbstractSocket::UnconnectedState) {
        m_transport->disconnectFromHost(); // Ensure that there is no connection
    }

    ConnectOperation *op = new ConnectOperation(this);
    // TODO: Connect error to op->setFinishedWithError()

    setStatus(Status::Connecting, StatusReason::Local);
//    setAuthState(AuthStateNone);
    m_transport->connectToHost(m_dcOption.address, m_dcOption.port);

    connect(m_transport, &CTelegramTransport::errorOccurred, op, [op] (QAbstractSocket::SocketError error, const QString &text) {
        op->setFinishedWithError({
                                     { QStringLiteral("qtError"), error },
                                     { QStringLiteral("qtErrorText"), text },
                                 });
    });
    connect(this, &Connection::statusChanged, op, [op] (Status status, StatusReason reason) {
        Q_UNUSED(reason)

        if (status == Status::HasDhKey) {
            op->setFinished();
        }
    });
//    connect(m_transport, &CTelegramTransport::stateChanged, [op] (QAbstractSocket::SocketState transportState) {
//        if (transportState == QAbstractSocket::ConnectedState) {
//            op->setFinished();
//        }
//    });

    return op;
}

void Connection::processSeeOthers(PendingRpcOperation *operation)
{
    if (m_status == Status::Disconnected) {
        connectToDcOld();
    }
    if (m_dhLayer->state() != DhLayer::State::HasKey) {
        qCDebug(c_clientConnectionCategory) << "processSeeOthers():" << "queue operation:" << TLValue::firstFromArray(operation->requestData());
        m_queuedOperations.append(operation);
        return;
    }
    quint64 messageId = rpcLayer()->sendRpc(operation);
    qCDebug(c_clientConnectionCategory) << "processSeeOthers():" << TLValue::firstFromArray(operation->requestData()) << "sent with new id" << messageId;
}

void Connection::onClientDhStateChanged()
{
    qCDebug(c_clientConnectionCategory) << Q_FUNC_INFO << m_dcOption.id << m_dcOption.address << "DH status:" << m_dhLayer->state();
    if (m_dhLayer->state() == BaseDhLayer::State::HasKey) {
        if (!m_rpcLayer->sessionId()) {
            rpcLayer()->startNewSession();
        }
        rpcLayer()->setServerSalt(m_dhLayer->serverSalt());
        if (!m_queuedOperations.isEmpty()) {
            for (PendingRpcOperation *operation : m_queuedOperations) {
                quint64 messageId = rpcLayer()->sendRpc(operation);
                qCDebug(c_clientConnectionCategory) << "Dequeue operation" << TLValue::firstFromArray(operation->requestData()) << "with new id" << messageId;
            }
            m_queuedOperations.clear();
        }
    }
}

bool Connection::processAuthKey(quint64 authKeyId)
{
    return authKeyId == m_sendHelper->authId();
}

} // Client namespace

} // Telegram namespace
