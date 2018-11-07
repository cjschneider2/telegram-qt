/*
   Copyright (C) 2018 Alexander Akulich <akulichalexander@gmail.com>

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

#ifndef TELEGRAMQT_FILE_DATA_STORAGE_HPP
#define TELEGRAMQT_FILE_DATA_STORAGE_HPP

#include "DataStorage.hpp"

namespace Telegram {

namespace Client {

class FileDataStorage : public DataStorage
{
    Q_OBJECT
public:
    explicit FileDataStorage(QObject *parent = nullptr);

};

} // Client namespace

} // Telegram namespace

#endif // TELEGRAMQT_FILE_DATA_STORAGE_HPP
