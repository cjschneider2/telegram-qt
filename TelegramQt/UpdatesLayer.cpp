#include "UpdatesLayer.hpp"

#include "ClientBackend.hpp"
#include "DataStorage.hpp"
#include "DataStorage_p.hpp"
#include "MessagingApi.hpp"
#include "MessagingApi_p.hpp"

#include "ClientRpcUpdatesLayer.hpp"

#include "TLTypesDebug.hpp"

#include <QLoggingCategory>

Q_LOGGING_CATEGORY(c_updatesLoggingCategory, "telegram.client.updates", QtDebugMsg)

namespace Telegram {

namespace Client {

UpdatesInternalApi::UpdatesInternalApi(QObject *parent) :
    QObject(parent)
{
}

void UpdatesInternalApi::sync()
{
    qDebug() << Q_FUNC_INFO;
    UpdatesRpcLayer::PendingUpdatesState *op = m_backend->updatesLayer()->getState();
    connect(op, &PendingOperation::finished, this, [op] () {
        TLUpdatesState res;
        op->getResult(&res);
        qDebug() << "res:" << res;
    });
}

void UpdatesInternalApi::setBackend(Backend *backend)
{
    m_backend = backend;
}

bool UpdatesInternalApi::processUpdates(const TLUpdates &updates)
{
    qCDebug(c_updatesLoggingCategory) << "updates:" << updates;

    //sync();

    DataInternalApi *internal = dataInternalApi();

    switch (updates.tlType) {
    case TLValue::UpdatesTooLong:
        qCDebug(c_updatesLoggingCategory) << "Updates too long!";
//        getUpdatesState();
        break;
    case TLValue::UpdateShortMessage:
    case TLValue::UpdateShortChatMessage:
    {
        // Reconstruct full update from this short update.
        TLUpdate update;

        if (update.message.toId.channelId) {
            update.tlType = TLValue::UpdateNewChannelMessage;
        } else {
            update.tlType = TLValue::UpdateNewMessage;
        }
        update.pts = updates.pts;
        update.ptsCount = updates.ptsCount;
        TLMessage &shortMessage = update.message;
        shortMessage.tlType = TLValue::Message;
        shortMessage.id = updates.id;
        shortMessage.flags = updates.flags;
        shortMessage.message = updates.message;
        shortMessage.date = updates.date;
        shortMessage.media.tlType = TLValue::MessageMediaEmpty;
        shortMessage.fwdFrom = updates.fwdFrom;
        shortMessage.replyToMsgId = updates.replyToMsgId;

//        int messageActionIndex = 0;
        if (updates.tlType == TLValue::UpdateShortMessage) {
            shortMessage.toId.tlType = TLValue::PeerUser;

            if (shortMessage.out()) {
                shortMessage.toId.userId = updates.userId;
                shortMessage.fromId = internal->selfUserId();
            } else {
                shortMessage.toId.userId = internal->selfUserId();
                shortMessage.fromId = updates.userId;
            }

//            messageActionIndex = TypingStatus::indexForUser(m_contactsMessageActions, updates.fromId);
//            if (messageActionIndex >= 0) {
//                emit contactMessageActionChanged(updates.fromId, TelegramNamespace::MessageActionNone);
//            }

        } else {
            shortMessage.toId.tlType = TLValue::PeerChat;
            shortMessage.toId.chatId = updates.chatId;

            shortMessage.fromId = updates.fromId;

//            messageActionIndex = TypingStatus::indexForUser(m_contactsMessageActions, updates.fromId);
//            if (messageActionIndex >= 0) {
//                emit contactChatMessageActionChanged(updates.chatId,
//                                                    updates.fromId,
//                                                    TelegramNamespace::MessageActionNone);
//            }
        }

        processUpdate(update);

//        if (messageActionIndex > 0) {
//            m_contactsMessageActions.remove(messageActionIndex);
//        }
    }
        break;
    case TLValue::UpdateShort:
        processUpdate(updates.update);
        break;
    case TLValue::UpdatesCombined:
        internal->processData(updates.users);
        internal->processData(updates.chats);
        qCDebug(c_updatesLoggingCategory) << Q_FUNC_INFO << "UpdatesCombined processing is not implemented yet.";
        for (int i = 0; i < updates.updates.count(); ++i) {
            processUpdate(updates.updates.at(i));
        }
        break;
    case TLValue::Updates:
        internal->processData(updates.users);
        internal->processData(updates.chats);

        // TODO: ensureUpdateState(, updates.seq, updates.date);?

        if (!updates.updates.isEmpty()) {
            // Official client sorts updates by pts/qts. Wat?!
            // Ok, let's see if there would be unordered updates.
            quint32 pts = updates.updates.first().pts;
            for (int i = 0; i < updates.updates.count(); ++i) {
                if (updates.updates.at(i).pts < pts) {
                    qCDebug(c_updatesLoggingCategory) << "Unordered update!";
                    //Q_ASSERT(0);
                }
                pts = updates.updates.at(i).pts;
            }

            // Initial implementation
            for (int i = 0; i < updates.updates.count(); ++i) {
                processUpdate(updates.updates.at(i));
            }
        }
        break;
    case TLValue::UpdateShortSentMessage:
        qCDebug(c_updatesLoggingCategory) << Q_FUNC_INFO << "UpdateShortSentMessage processing is not implemented yet.";
        //updateShortSentMessageId(id, updates.id);
        // TODO: Check that the follow state update is the right thing to do.
        // This fixes scenario: "send sendMessage" -> "receive UpdateShortSentMessage" -> "receive UpdateReadHistoryOutbox with update.pts == m_updatesState.pts + 2"
        //setUpdateState(m_updatesState.pts + 1, 0, 0);
        break;
    default:
        break;
    }
    return false;
}

bool UpdatesInternalApi::processUpdate(const TLUpdate &update)
{
#ifdef DEVELOPER_BUILD
    qCDebug(c_updatesLoggingCategory) << Q_FUNC_INFO << update;
#endif

    switch (update.tlType) {
    case TLValue::UpdateNewMessage:
    case TLValue::UpdateReadMessagesContents:
    case TLValue::UpdateReadHistoryInbox:
    case TLValue::UpdateReadHistoryOutbox:
    case TLValue::UpdateDeleteMessages:
    case TLValue::UpdateWebPage:
//        if (m_updatesState.pts > update.pts) {
//            qWarning() << "Why the hell we've got this update? Our pts:" << m_updatesState.pts << ", received:" << update.pts;
//            return;
//        }
//        if (m_updatesState.pts + update.ptsCount != update.pts) {
//            qDebug() << "Need inner updates:" << m_updatesState.pts << "+" << update.ptsCount << "!=" << update.pts;
//            qDebug() << "Updates delaying is not implemented yet. Recovery via getDifference() in 10 ms";
//            QTimer::singleShot(10, this, SLOT(getDifference()));
//            return;
//        }
        break;
    default:
        break;
    }

    switch (update.tlType) {
    case TLValue::UpdateNewMessage:
    case TLValue::UpdateNewChannelMessage:
    {
//        qCDebug(c_updatesLoggingCategory) << Q_FUNC_INFO << "UpdateNewMessage";
//        const Telegram::Peer peer = toPublicPeer(update.message.toId);
//        if (m_dialogs.contains(peer)) {
//            const TLDialog &dialog = m_dialogs.value(peer);
//            if (update.message.id <= dialog.topMessage) {
//                break;
//            }
//        }
        dataInternalApi()->processData(update.message);

        MessagingApiPrivate *messaging = MessagingApiPrivate::get(messagingApi());
        messaging->onMessageReceived(update.message);
    }
        break;
//    case TLValue::UpdateMessageID:
        //updateSentMessageId(update.randomId, update.id);
//        break;
        //    case TLValue::UpdateReadMessages:
        //        foreach (quint32 messageId, update.messages) {
        //            const QPair<QString, quint64> phoneAndId = m_messagesMap.value(messageId);
        //            emit sentMessageStatusChanged(phoneAndId.first, phoneAndId.second, TelegramNamespace::MessageDeliveryStatusRead);
        //        }
        //        ensureUpdateState(update.pts);
        //        break;
        //    case TLValue::UpdateDeleteMessages:
        //        update.messages;
        //        ensureUpdateState(update.pts);
        //        break;
        //    case TLValue::UpdateRestoreMessages:
        //        update.messages;
        //        ensureUpdateState(update.pts);
        //        break;
//    case TLValue::UpdateUserTyping:
//    case TLValue::UpdateChatUserTyping:
//        if (m_users.contains(update.userId)) {
//            TelegramNamespace::MessageAction action = telegramMessageActionToPublicAction(update.action.tlType);

//            int remainingTime = s_userTypingActionPeriod;
//            remainingTime += m_typingUpdateTimer->remainingTime();

//            int index = -1;
//            if (update.tlType == TLValue::UpdateUserTyping) {
//                index = TypingStatus::indexForUser(m_contactsMessageActions, update.userId);
//                emit contactMessageActionChanged(update.userId, action);
//            } else {
//                index = TypingStatus::indexForChatAndUser(m_contactsMessageActions, update.chatId, update.userId);
//                emit contactChatMessageActionChanged(update.chatId,
//                                                     update.userId, action);
//            }

//            if (index < 0) {
//                index = m_contactsMessageActions.count();
//                TypingStatus status;
//                status.userId = update.userId;
//                if (update.tlType == TLValue::UpdateChatUserTyping) {
//                    status.chatId = update.chatId;
//                }
//                m_contactsMessageActions.append(status);
//            }

//            m_contactsMessageActions[index].action = action;
//            m_contactsMessageActions[index].typingTime = remainingTime;

//            ensureTypingUpdateTimer(remainingTime);
//        }
//        break;
//    case TLValue::UpdateChatParticipants: {
//        TLChatFull newChatState = m_chatFullInfo.value(update.participants.chatId);
//        newChatState.id = update.participants.chatId; // newChatState can be newly created empty chat
//        newChatState.participants = update.participants;
//        updateFullChat(newChatState);

//        qDebug() << Q_FUNC_INFO << "chat id resolved to" << update.participants.chatId;
//        break;
//    }
//    case TLValue::UpdateUserStatus: {
//        if (update.userId == m_selfUserId) {
//            break;
//        }

//        TLUser *user = m_users.value(update.userId);
//        if (user) {
//            user->status = update.status;
//            emit contactStatusChanged(update.userId, getApiContactStatus(user->status.tlType));
//        }
//        break;
//    }
//    case TLValue::UpdateUserName: {
//        TLUser *user = m_users.value(update.userId);
//        if (user) {
//            bool changed = (user->firstName == update.firstName) && (user->lastName == update.lastName);
//            if (changed) {
//                user->firstName = update.firstName;
//                user->lastName = update.lastName;
//                user->username = update.username;
//                emit contactProfileChanged(update.userId);
//            }
//        }
//        break;
//    }
        //    case TLValue::UpdateUserPhoto:
        //        update.userId;
        //        update.date;
        //        update.photo;
        //        update.previous;
        //        break;
        //    case TLValue::UpdateContactRegistered:
        //        update.userId;
        //        update.date;
        //        break;
        //    case TLValue::UpdateContactLink:
        //        update.userId;
        //        update.myLink;
        //        update.foreignLink;
        //        break;
        //    case TLValue::UpdateActivation:
        //        update.userId;
        //        break;
        //    case TLValue::UpdateNewAuthorization:
        //        update.authKeyId;
        //        update.date;
        //        update.device;
        //        update.location;
        //        break;
        //    case TLValue::UpdateNewGeoChatMessage:
        //        update.message;
        //        break;
        //    case TLValue::UpdateNewEncryptedMessage:
        //        update.message;
        //        update.qts;
        //        break;
        //    case TLValue::UpdateEncryptedChatTyping:
        //        update.chatId;
        //        break;
        //    case TLValue::UpdateEncryption:
        //        update.chat;
        //        update.date;
        //        break;
        //    case TLValue::UpdateEncryptedMessagesRead:
        //        update.chatId;
        //        update.maxDate;
        //        update.date;
        //        break;
        //    case TLValue::UpdateChatParticipantAdd:
        //        update.chatId;
        //        update.userId;
        //        update.inviterId;
        //        update.version;
        //        break;
        //    case TLValue::UpdateChatParticipantDelete:
        //        update.chatId;
        //        update.userId;
        //        update.version;
        //        break;
//    case TLValue::UpdateDcOptions: {
//        int dcUpdatesReplaced = 0;
//        int dcUpdatesInserted = 0;
//        for (const TLDcOption &option : update.dcOptions) {
//            if (ensureDcOption(&m_dcConfiguration, option)) {
//                ++dcUpdatesReplaced;
//            } else {
//                ++dcUpdatesInserted;
//            }
//        }

//        qDebug() << Q_FUNC_INFO << "Dc configuration update replaces" << dcUpdatesReplaced << "options (" << dcUpdatesInserted << "options inserted).";
//        break;
//    }
        //    case TLValue::UpdateUserBlocked:
        //        update.userId;
        //        update.blocked;
        //        break;
        //    case TLValue::UpdateNotifySettings:
        //        update.peer;
        //        update.notifySettings;
        //        break;
//    case TLValue::UpdateReadHistoryInbox:
//    case TLValue::UpdateReadHistoryOutbox:
//    {
//        const Telegram::Peer peer = toPublicPeer(update.peer);
//        if (!peer.isValid()) {
//#ifdef DEVELOPER_BUILD
//            qDebug() << Q_FUNC_INFO << update.tlType << "Unable to resolve peer" << update.peer;
//#else
//            qDebug() << Q_FUNC_INFO << update.tlType << "Unable to resolve peer" << update.peer.tlType << update.peer.userId << update.peer.chatId;
//#endif
//        }
//        if (m_dialogs.contains(peer)) {
//            m_dialogs[peer].readInboxMaxId = update.maxId;
//        }
//        if (update.tlType == TLValue::UpdateReadHistoryInbox) {
//            emit messageReadInbox(peer, update.maxId);
//        } else {
//            emit messageReadOutbox(peer, update.maxId);
//        }
//        break;
//    }
//    case TLValue::UpdateReadChannelInbox:
//    {
//        const Telegram::Peer peer = Telegram::Peer(update.channelId, Telegram::Peer::Channel);
//        if (m_dialogs.contains(peer)) {
//            m_dialogs[peer].readInboxMaxId = update.maxId;
//        }
//        emit messageReadInbox(peer, update.maxId);
//    }
//        break;
//    default:
//        qDebug() << Q_FUNC_INFO << "Update type" << update.tlType << "is not implemented yet.";
//        break;
//    }

//    switch (update.tlType) {
//    case TLValue::UpdateNewMessage:
//    case TLValue::UpdateReadMessagesContents:
//    case TLValue::UpdateReadHistoryInbox:
//    case TLValue::UpdateReadHistoryOutbox:
//    case TLValue::UpdateDeleteMessages:
//    case TLValue::UpdateWebPage:
//        ensureUpdateState(update.pts);
//        break;
//    case TLValue::UpdateNewChannelMessage:
//    {
//        const Telegram::Peer peer = toPublicPeer(update.message.toId);
//        if (m_dialogs.contains(peer)) {
//            m_dialogs[peer].pts = update.pts;
//        }
//    }
//        break;
//    case TLValue::UpdateDeleteChannelMessages:
//    {
//        const Telegram::Peer peer = Telegram::Peer(update.channelId, Telegram::Peer::Channel);
//        qDebug() << Q_FUNC_INFO << "DeleteChannelMessages is not implemented yet" << update.channelId << update.messages << update.pts << update.ptsCount;
//        if (m_dialogs.contains(peer)) {
//            m_dialogs[peer].pts = update.pts;
//        }
//    }
//        break;
    default:
        break;
    }

    return false;
}

MessagingApi *UpdatesInternalApi::messagingApi()
{
    return m_backend->messagingApi();
}

DataStorage *UpdatesInternalApi::dataStorage()
{
    return m_backend->dataStorage();
}

DataInternalApi *UpdatesInternalApi::dataInternalApi()
{
    return DataInternalApi::get(dataStorage());
}

} // Client namespace

} // Telegram namespace
