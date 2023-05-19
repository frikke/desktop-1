#pragma once
/*
 * Copyright (C) 2023 by Oleksandr Zolotov <alex@nextcloud.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 */

#include "accountfwd.h"
#include <csync.h>
#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QObject>
#include <QSet>
#include <QSslKey>
#include <QString>
#include <QVector>

class QSslCertificate;
class QJsonDocument;
namespace OCC
{
class OWNCLOUDSYNC_EXPORT FolderMetadata : public QObject
{
    Q_OBJECT
    // represents a user that has access to a folder for which metadata instance is created
    struct FolderUser {
        QString userId;
        QByteArray certificatePem;
        QByteArray encryptedMetadataKey;
        QByteArray encryptedFiledropKey;
    };

public:
    enum MetadataVersion {
        VersionUndefined = -1,
        Version1,
        Version1_2,
        Version2_0,
    };

    struct EncryptedFile {
        QByteArray encryptionKey;
        QByteArray mimetype;
        QByteArray initializationVector;
        QByteArray authenticationTag;
        QString encryptedFilename;
        QString originalFilename;
    };

    struct OWNCLOUDSYNC_EXPORT RootEncryptedFolderInfo {
        explicit RootEncryptedFolderInfo(const QString &remotePath,
                                         const QByteArray &encryptionKey = {},
                                         const QByteArray &decryptionKey = {},
                                         const QSet<QByteArray> &checksums = {});

        static RootEncryptedFolderInfo makeDefault();

        QString path;
        QByteArray keyForEncryption;
        QByteArray keyForDecryption;
        QSet<QByteArray> keyChecksums;
        [[nodiscard]] bool keysSet() const;
    };

    FolderMetadata(AccountPtr account);

    FolderMetadata(AccountPtr account,
                   const QByteArray &metadata,
                   const RootEncryptedFolderInfo &rootEncryptedFolderInfo,
                   QObject *parent = nullptr);

    [[nodiscard]] QVector<EncryptedFile> files() const;

    [[nodiscard]] bool isValid() const;

    [[nodiscard]] bool isFileDropPresent() const;

    [[nodiscard]] bool encryptedMetadataNeedUpdate() const;

    [[nodiscard]] bool moveFromFileDropToFiles();

    const QByteArray &fileDrop() const;

    bool addUser(const QString &userId, const QSslCertificate &certificate);
    bool removeUser(const QString &userId);

    [[nodiscard]] const QByteArray metadataKeyForEncryption() const;
    [[nodiscard]] const QByteArray metadataKeyForDecryption() const;
    const QSet<QByteArray> &keyChecksums() const;

    QByteArray encryptedMetadata();

    [[nodiscard]] MetadataVersion existingMetadataVersion() const;
    [[nodiscard]] MetadataVersion encryptedMetadataVersion() const;

    [[nodiscard]] bool isVersion2AndUp() const;

    static MetadataVersion latestSupportedMetadataVersion(const double versionFromApi);

    static EncryptionStatusEnums::ItemEncryptionStatus fromMedataVersionToItemEncryptionStatus(const MetadataVersion &metadataVersion);

private:
    QByteArray encryptedMetadataLegacy();

    [[nodiscard]] bool verifyMetadataKey(const QByteArray &metadataKey) const;

    [[nodiscard]] QByteArray encryptDataWithPublicKey(const QByteArray &data, const QSslKey key) const;
    [[nodiscard]] QByteArray decryptDataWithPrivateKey(const QByteArray &data) const;

    [[nodiscard]] QByteArray encryptJsonObject(const QByteArray& obj, const QByteArray pass) const;
    [[nodiscard]] QByteArray decryptJsonObject(const QByteArray& encryptedJsonBlob, const QByteArray& pass) const;

    [[nodiscard]] bool checkMetadataKeyChecksum(const QByteArray &metadataKey, const QByteArray &metadataKeyChecksum) const;

    [[nodiscard]] QByteArray computeMetadataKeyChecksum(const QByteArray &metadataKey) const;

    [[nodiscard]] EncryptedFile parseEncryptedFileFromJson(const QString &encryptedFilename, const QJsonValue &fileJSON) const;

    [[nodiscard]] QJsonObject convertFileToJsonObject(const EncryptedFile *encryptedFile, const QByteArray &metadataKey) const;

public slots:
    void addEncryptedFile(const EncryptedFile &f);
    void removeEncryptedFile(const EncryptedFile &f);
    void removeAllEncryptedFiles();
    void setMetadataKeyForEncryption(const QByteArray &metadataKeyForDecryption);
    void setMetadataKeyForDecryption(const QByteArray &metadataKeyForDecryption);
    void setKeyChecksums(const QSet<QByteArray> &keyChecksums);

private slots:
    void setupMetadata();
    void setupEmptyMetadata();
    void setupEmptyMetadataLegacy();
    void setupExistingMetadata(const QByteArray &metadata);
    void setupExistingLegacyMetadataForMigration(const QByteArray &metadata);
    void setupVersionFromExistingMetadata(const QByteArray &metadata);

    void startFetchRootE2eeFolderMetadata(const QString &path);
    void fetchRootE2eeFolderMetadata(const QByteArray &folderId);
    void rootE2eeFolderEncryptedIdReceived(const QStringList &list);
    void rootE2eeFolderEncryptedIdError(QNetworkReply *reply);
    void rootE2eeFolderMetadataReceived(const QJsonDocument &json, int statusCode);
    void rotE2eeFolderEncryptedMetadataError(const QByteArray &fileId, int httpReturnCode);

    void updateUsersEncryptedMetadataKey();
    void createNewMetadataKeyForEncryption();

    void emitSetupComplete();

signals:
    void setupComplete();

private:
    AccountPtr _account;
    QByteArray _initialMetadata;

    bool _isRootEncryptedFolder = true;
    QByteArray _metadataKeyForEncryption;
    QByteArray _metadataKeyForDecryption; // used for storing initial metadataKey to use for decryption, especially in nested folders when changing the metadataKey and re-encrypting nested dirs

    QSet<QByteArray> _keyChecksums;
    QByteArray _metadataNonce;

    QByteArray _fileDropMetadataNonceBase64;
    QByteArray _fileDropMetadataAuthenticationTag;
    QByteArray _fileDropKey;
    QByteArray _fileDropCipherTextEncryptedAndBase64;
    QJsonObject _fileDrop;
    // used by unit tests, must get assigned simultaneously with _fileDrop and not erased
    QJsonObject _fileDropFromServer;

    QMap<int, QByteArray> _metadataKeys; //legacy, remove after migration is done

    QHash<QString, FolderUser> _folderUsers;

    MetadataVersion _existingMetadataVersion = MetadataVersion::VersionUndefined;
    MetadataVersion _encryptedMetadataVersion = MetadataVersion::VersionUndefined;

    QVector<QPair<QString, QString>> _sharing;

    QVector<EncryptedFile> _files;
    bool _isMetadataValid = false;
};

} // namespace OCC
