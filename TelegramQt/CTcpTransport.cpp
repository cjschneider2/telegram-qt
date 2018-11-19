/*
   Copyright (C) 2014-2017 Alexandr Akulich <akulichalexander@gmail.com>

   This file is a part of TelegramQt library.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

 */

#include "AesCtr.hpp"
#include "CTcpTransport.hpp"
#include "CRawStream.hpp"

#include <QHostAddress>
#include <QTimer>

#include <QLoggingCategory>

using namespace Telegram;

#ifndef Q_FALLTHROUGH
#define Q_FALLTHROUGH() (void)0
#endif

Q_LOGGING_CATEGORY(c_loggingTcpTransport, "telegram.transport.tcp", QtWarningMsg)

static const quint32 tcpTimeout = 15 * 1000;

CTcpTransport::CTcpTransport(QObject *parent) :
    CTelegramTransport(parent),
    m_socket(nullptr),
    m_timeoutTimer(new QTimer(this))
{
    m_timeoutTimer->setInterval(tcpTimeout);
    connect(m_timeoutTimer, &QTimer::timeout, this, &CTcpTransport::onTimeout);
}

CTcpTransport::~CTcpTransport()
{
    if (m_socket && m_socket->isWritable() && m_socket->isOpen()
            && m_socket->state() != QAbstractSocket::UnconnectedState) {
        m_socket->waitForBytesWritten(100);
        m_socket->disconnectFromHost();
    }
}

QString CTcpTransport::remoteAddress() const
{
    return m_socket ? m_socket->peerAddress().toString() : QString();
}

void CTcpTransport::connectToHost(const QString &ipAddress, quint32 port)
{
    qCDebug(c_loggingTcpTransport) << this << Q_FUNC_INFO << ipAddress << port;
    m_socket->connectToHost(ipAddress, port);
}

void CTcpTransport::disconnectFromHost()
{
    qCDebug(c_loggingTcpTransport) << this << Q_FUNC_INFO;
    if (m_socket) {
        m_socket->disconnectFromHost();
    }
    m_readBuffer.clear();
    m_packetNumber = 0;
    m_expectedLength = 0;
    m_sessionType = Unknown;
}

CTcpTransport::SessionType CTcpTransport::sessionType() const
{
    return m_sessionType;
}

void CTcpTransport::sendPackageImplementation(const QByteArray &payload)
{
    qCDebug(c_loggingTcpTransport) << this << Q_FUNC_INFO << payload.size();

    // quint32 length (included length itself + packet number + crc32 + payload (MUST be divisible by 4)
    // quint32 packet number
    // quint32 CRC32 (length, quint32 packet number, payload)
    // Payload

    // Abridged version:
    // quint8: 0xef
    // DataLength / 4 < 0x7f ?
    //      (quint8: Packet length / 4) :
    //      (quint8: 0x7f, quint24: Packet length / 4)
    // Payload

    if (payload.length() % 4) {
        qCCritical(c_loggingTcpTransport) << this << Q_FUNC_INFO
                                          << "Invalid outgoing package! "
                                             "The payload size is not divisible by four!";
    }

    QByteArray package;
    package.reserve(payload.size() + 4);
    const quint32 length = payload.length() / 4;
    if (length < 0x7f) {
        package.append(char(length));
    } else {
        package.append(char(0x7f));
        package.append(reinterpret_cast<const char *>(&length), 3);
    }
    package.append(payload);

    if (m_writeAesContext && m_writeAesContext->hasKey()) {
        package = m_writeAesContext->crypt(package);
    }

    m_socket->write(package);
}

void CTcpTransport::setSessionType(CTcpTransport::SessionType sessionType)
{
    m_sessionType = sessionType;
}

void CTcpTransport::resetCryptoKeys()
{
    delete m_readAesContext;
    m_readAesContext = nullptr;
    delete m_writeAesContext;
    m_writeAesContext = nullptr;
}

void CTcpTransport::setCryptoKeysSourceData(const QByteArray &source, SourceRevertion revertion)
{
    if (source.size() != (Crypto::AesCtrContext::KeySize + Crypto::AesCtrContext::IvecSize)) {
        qCWarning(c_loggingTcpTransport) << this << Q_FUNC_INFO << "Invalid input data (size mismatch)";
        return;
    }
    QByteArray reversed = source;
    std::reverse(reversed.begin(), reversed.end());
    const auto setSourceData = [](const QByteArray &source, Crypto::AesCtrContext *&context) {
        if (!context) {
            context = new Crypto::AesCtrContext();
        }
        context->setKey(source.left(Crypto::AesCtrContext::KeySize));
        context->setIVec(source.mid(Crypto::AesCtrContext::KeySize));
    };
    if (revertion == DirectIsReadReversedIsWrite) {
        setSourceData(source, m_readAesContext);
        setSourceData(reversed, m_writeAesContext);
    } else { // Server, DirectIsWriteReversedIsRead
        setSourceData(source, m_writeAesContext);
        setSourceData(reversed, m_readAesContext);
    }
    const char *className = metaObject()->className();
    if (strstr(className, "Server")) {
        m_readAesContext->setDescription(QByteArrayLiteral("server read"));
        m_writeAesContext->setDescription(QByteArrayLiteral("server write"));
    } else if (strstr(className, "Client")) {
        m_readAesContext->setDescription(QByteArrayLiteral("client read"));
        m_writeAesContext->setDescription(QByteArrayLiteral("client write"));
    }
}

void CTcpTransport::setState(QAbstractSocket::SocketState newState)
{
    qCDebug(c_loggingTcpTransport) << this << Q_FUNC_INFO << newState;
    switch (newState) {
    case QAbstractSocket::HostLookupState:
    case QAbstractSocket::ConnectingState:
        m_timeoutTimer->start();
        break;
    case QAbstractSocket::ConnectedState:
        m_expectedLength = 0;
        setSessionType(Unknown);
        Q_FALLTHROUGH();
    default:
        m_timeoutTimer->stop();
        break;
    }
    CTelegramTransport::setState(newState);
}

void CTcpTransport::onReadyRead()
{
    qCDebug(c_loggingTcpTransport) << this << Q_FUNC_INFO << m_socket->bytesAvailable();
    readEvent();
    if (m_sessionType == Unknown) {
        qCCritical(c_loggingTcpTransport) << "Unknown session type!";
        return;
    }
    if (m_socket->bytesAvailable() > 0) {
        QByteArray allData = m_socket->readAll();
        if (m_readAesContext) {
            allData = m_readAesContext->crypt(allData);
        }
        m_readBuffer.append(allData);
    }
    while (m_readBuffer.size() >= 4) {
        if (m_expectedLength == 0) {
            const quint8 *data = reinterpret_cast<const quint8*>(m_readBuffer.constData());
            quint8 length_t1 = data[0];
            if (length_t1 < 0x7fu) {
                m_expectedLength = length_t1 * 4;
                m_readBuffer = m_readBuffer.mid(1);
            } else if (length_t1 == 0x7fu) {
                m_expectedLength = data[1] + data[2] * 256 + data[3] * 256 * 256;
                m_expectedLength *= 4;
                m_readBuffer = m_readBuffer.mid(4);
            } else {
                qCWarning(c_loggingTcpTransport) << this << "Invalid packet size byte" << hex << showbase << length_t1;
                setError(QAbstractSocket::UnknownSocketError, QStringLiteral("Invalid read operation"));
                disconnectFromHost();
                return;
            }
        }
        if (m_readBuffer.size() < static_cast<qint64>(m_expectedLength)) {
            qCDebug(c_loggingTcpTransport) << this << Q_FUNC_INFO << "Ready read, but only "
                                           << m_readBuffer.size() << "bytes available ("
                                           << m_expectedLength << "bytes expected)";
            return;
        }
        const QByteArray readPackage = m_readBuffer.left(m_expectedLength);
        m_readBuffer = m_readBuffer.mid(m_expectedLength);
        m_expectedLength = 0;
        qCDebug(c_loggingTcpTransport) << this << Q_FUNC_INFO
                                         << "Received a package (" << readPackage.size() << " bytes)";
        emit packageReceived(readPackage);
    }
}

void CTcpTransport::onTimeout()
{
    qCDebug(c_loggingTcpTransport) << this << Q_FUNC_INFO << m_socket->peerName() << m_socket->peerPort();
    emit timeout();
    m_socket->disconnectFromHost();
}

void CTcpTransport::onSocketErrorOccurred(QAbstractSocket::SocketError error)
{
    setError(error, m_socket->errorString());
}

void CTcpTransport::setSocket(QAbstractSocket *socket)
{
    if (m_socket) {
        qCCritical(c_loggingTcpTransport()) << this << Q_FUNC_INFO << "An attempt to set a socket twice";
    }
    m_socket = socket;
    connect(m_socket, &QAbstractSocket::stateChanged, this, &CTcpTransport::setState);
    connect(m_socket, SIGNAL(error(QAbstractSocket::SocketError)), SLOT(onSocketErrorOccurred(QAbstractSocket::SocketError)));
    connect(m_socket, &QIODevice::readyRead, this, &CTcpTransport::onReadyRead);
}
