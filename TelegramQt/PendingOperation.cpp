#include "PendingOperation.hpp"
#include "PendingOperation_p.hpp"

#include <QLoggingCategory>

namespace Telegram {

PendingOperation::PendingOperation(QObject *parent) :
    QObject(parent),
    m_finished(false),
    m_succeeded(true)
{
}

PendingOperation::~PendingOperation()
{
    delete d;
}

QString PendingOperation::c_text()
{
    return QStringLiteral("text");
}

void PendingOperation::startLater()
{
    QMetaObject::invokeMethod(this, [this] (){ start(); }, Qt::QueuedConnection);
}

void PendingOperation::runAfter(PendingOperation *operation)
{
    connect(operation, &PendingOperation::succeeded, this, &PendingOperation::start);
    connect(operation, &PendingOperation::failed, this, &PendingOperation::onPreviousFailed);
    if (operation->isFinished()) {
        if (operation->isSucceeded()) {
            startLater();
        } else {
            setDelayedFinishedWithError(operation->errorDetails());
        }
    }
}

void PendingOperation::setFinished()
{
    qDebug() << "finished" << this;
    if (m_finished) {
        qWarning() << "Operation is already finished" << this;
        return;
    }
    m_finished = true;
    if (m_succeeded) {
        emit succeeded(this);
    } else {
        emit failed(this, m_errorDetails);
    }
    emit finished(this);
}

void PendingOperation::setFinishedWithError(const QVariantHash &details)
{
    qDebug() << "finished with error" << this << details;
    m_succeeded = false;
    m_errorDetails = details;
    setFinished();
}

void PendingOperation::setDelayedFinishedWithError(const QVariantHash &details)
{
    QMetaObject::invokeMethod(this, "setFinishedWithError", Qt::QueuedConnection, Q_ARG(QVariantHash, details)); // Invoke after return
}

void PendingOperation::clearResult()
{
    m_finished = false;
    m_succeeded = true;
    m_errorDetails.clear();
}

void PendingOperation::onPreviousFailed(PendingOperation *operation, const QVariantHash &details)
{
    Q_UNUSED(operation)
    setFinishedWithError(details);
}

SucceededPendingOperation::SucceededPendingOperation(QObject *parent) :
    PendingOperation(parent)
{
}

void SucceededPendingOperation::start()
{
    QMetaObject::invokeMethod(this, "setFinished", Qt::QueuedConnection);
}

} // Telegram namespace
