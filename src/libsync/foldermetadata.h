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
#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QObject>
#include <QSet>
#include <QSharedPointer>
#include <QSslCertificate>
#include <QSslKey>
#include <QString>
#include <QVector>

class QJsonDocument;
namespace OCC
{
class OWNCLOUDSYNC_EXPORT FolderMetadata : public QObject
{
    Q_OBJECT
    struct FolderUser {
        QString userId;
        QByteArray certificatePem;
        QByteArray encryptedMetadataKey;
        QByteArray encryptedFiledropKey;
    };

public:
    enum class RequiredMetadataVersion {
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

    struct OWNCLOUDSYNC_EXPORT TopLevelFolderInitializationData {
        explicit TopLevelFolderInitializationData(const QString &path,
                                         const QByteArray &keyForEncryption = {},
                                         const QByteArray &keyForDecryption = {},
                                         const QSet<QByteArray> &checksums = QSet<QByteArray>{});
        static TopLevelFolderInitializationData makeDefault();
        QString topLevelFolderPath;
        QByteArray metadataKeyForEncryption;
        QByteArray metadataKeyForDecryption;
        QSet<QByteArray> keyChecksums;
        [[nodiscard]] bool keysSet() const;
    };

    FolderMetadata(AccountPtr account);

    FolderMetadata(AccountPtr account,
                   RequiredMetadataVersion requiredMetadataVersion,
                   const QByteArray &metadata,
                   const TopLevelFolderInitializationData &topLevelFolderInitializationData,
                   QObject *parent = nullptr);

    FolderMetadata(AccountPtr account,
                   const QByteArray &metadata,
                   const TopLevelFolderInitializationData &topLevelFolderInitializationData,
                   QObject *parent = nullptr);

    [[nodiscard]] QVector<EncryptedFile> files() const;

    [[nodiscard]] bool isMetadataSetup() const;

    [[nodiscard]] bool isFileDropPresent() const;

    [[nodiscard]] bool encryptedMetadataNeedUpdate() const;

    [[nodiscard]] bool moveFromFileDropToFiles();

    [[nodiscard]] bool isTopLevelFolder() const;

    const QByteArray &fileDrop() const;

    bool addUser(const QString &userId, const QSslCertificate certificate);
    bool removeUser(const QString &userId);

    [[nodiscard]] const QByteArray metadataKeyForEncryption() const;
    const QSet<QByteArray> &keyChecksums() const;
    QString versionFromMetadata() const;

    QByteArray encryptedMetadata();

    [[nodiscard]] RequiredMetadataVersion metadataVersion() const;

    [[nodiscard]] bool isVersion2AndUp() const;

    [[nodiscard]] const QByteArray metadataKeyForDecryption() const;

private:
    /* Use std::string and std::vector internally on this class
     * to ease the port to Nlohmann Json API
     */
    [[nodiscard]] bool verifyMetadataKey(const QByteArray &metadataKey) const;

    [[nodiscard]] QByteArray encryptData(const QByteArray &data) const;
    [[nodiscard]] QByteArray encryptData(const QByteArray &data, const QSslKey key) const;
    [[nodiscard]] QByteArray decryptData(const QByteArray &data) const;

    [[nodiscard]] QByteArray encryptJsonObject(const QByteArray& obj, const QByteArray pass) const;
    [[nodiscard]] QByteArray decryptJsonObject(const QByteArray& encryptedJsonBlob, const QByteArray& pass) const;

    [[nodiscard]] bool checkMetadataKeyChecksum(const QByteArray &metadataKey, const QByteArray &metadataKeyChecksum) const;

    [[nodiscard]] QByteArray computeMetadataKeyChecksum(const QByteArray &metadataKey) const;

    [[nodiscard]] EncryptedFile parseEncryptedFileFromJson(const QString &encryptedFilename, const QJsonValue &fileJSON) const;

    [[nodiscard]] QJsonObject convertFileToJsonObject(const EncryptedFile *encryptedFile, const QByteArray &metadataKey) const;

    static QByteArray gZipEncryptAndBase64Encode(const QByteArray &key, const QByteArray &inputData, const QByteArray &iv, QByteArray &returnTag);
    static QByteArray base64DecodeDecryptAndGzipUnZip(const QByteArray &key, const QByteArray &inputData, const QByteArray &iv);

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
    void setupExistingMetadata(const QByteArray &metadata);
    void setupExistingLegacyMetadataForMigration(const QByteArray &metadata);
    void setupVersionFromExistingMetadata(const QByteArray &metadata);

    void startFetchTopLevelFolderMetadata();
    void fetchTopLevelFolderMetadata(const QByteArray &folderId);
    void topLevelFolderEncryptedIdReceived(const QStringList &list);
    void topLevelFolderEncryptedIdError(QNetworkReply *reply);
    void topLevelFolderEncryptedMetadataReceived(const QJsonDocument &json, int statusCode);
    void topLevelFolderEncryptedMetadataError(const QByteArray &fileId, int httpReturnCode);

    void updateUsersEncryptedMetadataKey();
    void createNewMetadataKeyForEncryption();
    void emitSetupComplete();

signals:
    void setupComplete();

private:
    QVector<EncryptedFile> _files;
    QByteArray _metadataKeyForEncryption;
    QByteArray _metadataKeyForDecryption; // used for storing initial metadataKey to use for decryption, especially in nested folders when changing the metadataKey and re-encrypting nested dirs
    QByteArray _metadataNonce;
    QByteArray _fileDropMetadataNonce;
    QByteArray _fileDropMetadataAuthenticationTag;
    QByteArray _fileDropKey;
    QMap<int, QByteArray> _metadataKeys; //legacy, remove after migration is done
    QSet<QByteArray> _keyChecksums;
    QHash<QString, FolderUser> _folderUsers;
    AccountPtr _account;
    RequiredMetadataVersion _requiredMetadataVersion = RequiredMetadataVersion::Version1_2;
    QVector<QPair<QString, QString>> _sharing;
    QByteArray _fileDropCipherTextEncryptedAndBase64;
    QByteArray _initialMetadata;
    QString _topLevelFolderPath;
    QString _versionFromMetadata;
    QJsonObject _fileDrop;
    // used by unit tests, must get assigned simultaneously with _fileDrop and not erased
    QJsonObject _fileDropFromServer;
    bool _isMetadataSetup = false;
    bool _migrationNeeded = false;
};

} // namespace OCC
