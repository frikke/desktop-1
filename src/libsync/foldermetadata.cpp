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

#include "account.h"
#include "foldermetadata.h"
#include "clientsideencryption.h"
#include "clientsideencryptionjobs.h"
#include <common/checksums.h>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSslCertificate>

namespace OCC
{
Q_LOGGING_CATEGORY(lcCseMetadata, "nextcloud.metadata", QtInfoMsg)

namespace
{
constexpr auto authenticationTagKey = "authenticationTag";
constexpr auto cipherTextKey = "ciphertext";
constexpr auto filesKey = "files";
constexpr auto filedropKey = "filedrop";
constexpr auto foldersKey = "folders";
constexpr auto initializationVectorKey = "initializationVector";
constexpr auto keyChecksumsKey = "keyChecksums";
constexpr auto metadataJsonKey = "metadata";
constexpr auto metadataKeyKey = "metadataKey";
constexpr auto metadataKeysKey = "metadataKeys";
constexpr auto nonceKey = "nonce";
constexpr auto usersKey = "users";
constexpr auto usersUserIdKey = "userId";
constexpr auto usersCertificateKey = "certificate";
constexpr auto usersEncryptedMetadataKey = "encryptedMetadataKey";
constexpr auto usersEncryptedFiledropKey = "encryptedFiledropKey";
constexpr auto versionKey = "version";
constexpr auto encryptedKey = "encrypted";

const auto metadataKeySize = 16;

QString metadataStringFromOCsDocument(const QJsonDocument &ocsDoc)
{
    return ocsDoc.object()["ocs"].toObject()["data"].toObject()["meta-data"].toString();
}
}

FolderMetadata::RootEncryptedFolderInfo::RootEncryptedFolderInfo(const QString &remotePath,
                                 const QByteArray &encryptionKey,
                                 const QByteArray &decryptionKey,
                                 const QSet<QByteArray> &checksums):
    path(remotePath),
    keyForEncryption(encryptionKey),
    keyForDecryption(decryptionKey), 
    keyChecksums(checksums)
{
}

FolderMetadata::RootEncryptedFolderInfo FolderMetadata::RootEncryptedFolderInfo::makeDefault()
{
    return RootEncryptedFolderInfo{QStringLiteral("/")};
}

bool FolderMetadata::RootEncryptedFolderInfo::keysSet() const
{
    return !keyForEncryption.isEmpty() && !keyForDecryption.isEmpty() && !keyChecksums.isEmpty();
}

FolderMetadata::FolderMetadata(AccountPtr account)
    : _account(account),
    _isRootEncryptedFolder(true)
{
    qCInfo(lcCseMetadata()) << "Setting up an Empty Metadata";
    setupEmptyMetadata();
}

FolderMetadata::FolderMetadata(AccountPtr account,
                               const QByteArray &metadata,
                               const RootEncryptedFolderInfo &rootEncryptedFolderInfo,
                               QObject *parent)
    : QObject(parent)
    , _account(account)
    , _initialMetadata(metadata)
    , _isRootEncryptedFolder(rootEncryptedFolderInfo.path == QStringLiteral("/"))
    , _metadataKeyForEncryption(rootEncryptedFolderInfo.keyForEncryption)
    , _metadataKeyForDecryption(rootEncryptedFolderInfo.keyForDecryption)
    , _keyChecksums(rootEncryptedFolderInfo.keyChecksums)
{
    setupVersionFromExistingMetadata(metadata);

    const auto doc = QJsonDocument::fromJson(metadata);
    qCInfo(lcCseMetadata()) << doc.toJson(QJsonDocument::Compact);
    const auto metaDataStr = metadataStringFromOCsDocument(doc);
    const auto metadataBase64 = metadata.toBase64();
    //----------------------------------------
    QByteArray metadatBase64WithBreaks;
    int j = 0;
    for (int i = 0; i < metadataBase64.size(); ++i) {
        metadatBase64WithBreaks += metadataBase64[i];
        ++j;
        if (j > 64) {
            j = 0;
            metadatBase64WithBreaks += '\n';
        }
    }
    const auto metadataSignature = _account->e2e()->generateSignatureCMS(metadatBase64WithBreaks);
    //--------------------------
    if (!_isRootEncryptedFolder
        && !rootEncryptedFolderInfo.keysSet()
        && !rootEncryptedFolderInfo.path.isEmpty()) {
        startFetchRootE2eeFolderMetadata(rootEncryptedFolderInfo.path);
    } else {
        setupMetadata();
    }
}

void FolderMetadata::setupMetadata()
{
    if (_initialMetadata.isEmpty()) {
        qCInfo(lcCseMetadata()) << "Setting up empty metadata";
        setupEmptyMetadata();
        return;
    }

    qCInfo(lcCseMetadata()) << "Setting up existing metadata";
    setupExistingMetadata(_initialMetadata);

    if (metadataKeyForDecryption().isEmpty() || metadataKeyForEncryption().isEmpty()) {
        qCWarning(lcCseMetadata()) << "Failed to setup FolderMetadata. Could not parse/create metadataKey!";
    }
    emitSetupComplete();
}

void FolderMetadata::setupExistingMetadata(const QByteArray &metadata)
{
    const auto doc = QJsonDocument::fromJson(metadata);
    qCDebug(lcCseMetadata()) << "Got existing metadata:" << doc.toJson(QJsonDocument::Compact);

    if (static_cast<int>(existingMetadataVersion()) < MetadataVersion::Version1) {
        qCDebug(lcCseMetadata()) << "Could not setup metadata. Incorrect version" << existingMetadataVersion();
        return;
    }
    if (static_cast<int>(existingMetadataVersion()) < MetadataVersion::Version2_0) {
        setupExistingLegacyMetadataForMigration(metadata);
        return;
    }
    
    qCDebug(lcCseMetadata()) << "Setting up latest metadata version" << existingMetadataVersion();
    const auto metaDataStr = metadataStringFromOCsDocument(doc);
    const auto metaDataDoc = QJsonDocument::fromJson(metaDataStr.toLocal8Bit());

    const auto fileDropObject = metaDataDoc.object().value(filedropKey).toObject();
    _fileDropCipherTextEncryptedAndBase64 = fileDropObject.value(cipherTextKey).toString().toLocal8Bit();
    _fileDropMetadataAuthenticationTag = QByteArray::fromBase64(fileDropObject.value(authenticationTagKey).toString().toLocal8Bit());
    _fileDropMetadataNonceBase64 = fileDropObject.value(nonceKey).toString().toLocal8Bit();

    const auto folderUsers = metaDataDoc[usersKey].toArray();
    QJsonDocument debugHelper;
    debugHelper.setArray(folderUsers);
    qCDebug(lcCseMetadata()) << "users: " << debugHelper.toJson(QJsonDocument::Compact);

    const auto isUsersArrayValid = (!_isRootEncryptedFolder && folderUsers.isEmpty()) || (_isRootEncryptedFolder && !folderUsers.isEmpty());
    Q_ASSERT(isUsersArrayValid);

    if (!isUsersArrayValid) {
        qCDebug(lcCseMetadata()) << "Could not decrypt metadata key. Users array is invalid!";
        return;
    }

    for (auto it = folderUsers.constBegin(); it != folderUsers.constEnd(); ++it) {
        const auto folderUserObject = it->toObject();
        const auto userId = folderUserObject.value(usersUserIdKey).toString();
        FolderUser folderUser;
        folderUser.userId = userId;
        folderUser.certificatePem = folderUserObject.value(usersCertificateKey).toString().toUtf8();
        folderUser.encryptedMetadataKey = QByteArray::fromBase64(folderUserObject.value(usersEncryptedMetadataKey).toString().toUtf8());
        folderUser.encryptedFiledropKey = QByteArray::fromBase64(folderUserObject.value(usersEncryptedFiledropKey).toString().toUtf8());
        _folderUsers[userId] = folderUser;
    }

    if (_folderUsers.contains(_account->davUser())) {
        const auto currentFolderUser = _folderUsers.value(_account->davUser());
        _metadataKeyForEncryption = decryptDataWithPrivateKey(currentFolderUser.encryptedMetadataKey);
        _metadataKeyForDecryption = _metadataKeyForEncryption;
        _fileDropKey = decryptDataWithPrivateKey(currentFolderUser.encryptedFiledropKey);
    }

    if (metadataKeyForDecryption().isEmpty() || metadataKeyForEncryption().isEmpty()) {
        qCDebug(lcCseMetadata()) << "Could not setup metadata key!";
        return;
    }
    
    const auto metadataObj = metaDataDoc.object()[metadataJsonKey].toObject();
    _metadataNonce = QByteArray::fromBase64(metadataObj[nonceKey].toString().toLocal8Bit());
    const auto cipherTextEncrypted = metadataObj[cipherTextKey].toString().toLocal8Bit();
    const auto cipherTextDecrypted = EncryptionHelper::decryptThenUnGzipData(metadataKeyForDecryption(), QByteArray::fromBase64(cipherTextEncrypted), _metadataNonce);
    if (cipherTextDecrypted.isEmpty()) {
        qCDebug(lcCseMetadata()) << "Could not decrypt cipher text!";
        return;
    }

    const auto cipherTextDocument = QJsonDocument::fromJson(cipherTextDecrypted);

    const auto keyCheckSums = cipherTextDocument[keyChecksumsKey].toArray();
    if (!keyCheckSums.isEmpty()) {
        _keyChecksums.clear();
    }
    for (auto it = keyCheckSums.constBegin(); it != keyCheckSums.constEnd(); ++it) {
        const auto keyChecksum = it->toVariant().toString().toUtf8();
        if (!keyChecksum.isEmpty()) {
            _keyChecksums.insert(keyChecksum);
        }
    }

    if (!verifyMetadataKey(metadataKeyForDecryption())) {
        qCDebug(lcCseMetadata()) << "Could not verify metadataKey!";
        return;
    }

    const auto files = cipherTextDocument.object()[filesKey].toObject();
    const auto folders = cipherTextDocument.object()[foldersKey].toObject();

    for (auto it = files.constBegin(), end = files.constEnd(); it != end; ++it) {
        const auto parsedEncryptedFile = parseEncryptedFileFromJson(it.key(), it.value());
        if (!parsedEncryptedFile.originalFilename.isEmpty()) {
            _files.push_back(parsedEncryptedFile);
        }
    }

    for (auto it = folders.constBegin(); it != folders.constEnd(); ++it) {
        const auto folderName = it.value().toString();
        if (!folderName.isEmpty()) {
            EncryptedFile file;
            file.encryptedFilename = it.key();
            file.originalFilename = folderName;
            _files.push_back(file);
        }
    }
    _isMetadataValid = true;
}

void FolderMetadata::setupExistingLegacyMetadataForMigration(const QByteArray &metadata)
{
    const auto doc = QJsonDocument::fromJson(metadata);
    qCDebug(lcCseMetadata()) << "Setting up legacy existing metadata version" << existingMetadataVersion() << doc.toJson(QJsonDocument::Compact);

    const auto metaDataStr = metadataStringFromOCsDocument(doc);
    const auto metaDataDoc = QJsonDocument::fromJson(metaDataStr.toLocal8Bit());
    const auto metadataObj = metaDataDoc.object()[metadataJsonKey].toObject();

    // we will use metadata key from metadata to decrypt legacy metadata, so let's clear the decryption key if any provided by top-level folder
    _metadataKeyForDecryption.clear();

    const auto metadataKeyFromJson = metadataObj[metadataKeyKey].toString().toLocal8Bit();
    if (!metadataKeyFromJson.isEmpty()) {
        // parse version 1.2
        const auto decryptedMetadataKeyBase64 = decryptDataWithPrivateKey(QByteArray::fromBase64(metadataKeyFromJson));
        if (!decryptedMetadataKeyBase64.isEmpty()) {
            // fromBase64() multiple times just to stick with the old wrong way
            _metadataKeyForDecryption = QByteArray::fromBase64(QByteArray::fromBase64(decryptedMetadataKeyBase64));
        }
    }

    if (metadataKeyForDecryption().isEmpty()
        && existingMetadataVersion() < latestSupportedMetadataVersion(_account->capabilities().clientSideEncryptionVersion())) {
        // parse version 1.0
        qCDebug(lcCseMetadata()) << "Migrating from" << existingMetadataVersion() << "to"
                                 << latestSupportedMetadataVersion(_account->capabilities().clientSideEncryptionVersion());
        const auto metadataKeys = metadataObj["metadataKeys"].toObject();
        if (metadataKeys.isEmpty()) {
            qCDebug(lcCseMetadata()) << "Could not migrate. No metadata keys found!";
            return;
        }

        const auto lastMetadataKeyFromJson = metadataKeys.keys().last().toLocal8Bit();
        if (!lastMetadataKeyFromJson.isEmpty()) {
            const auto lastMetadataKeyValueFromJson = metadataKeys.value(lastMetadataKeyFromJson).toString().toLocal8Bit();
            if (!lastMetadataKeyValueFromJson.isEmpty()) {
                const auto lastMetadataKeyValueFromJsonBase64 = decryptDataWithPrivateKey(QByteArray::fromBase64(lastMetadataKeyValueFromJson));
                if (!lastMetadataKeyValueFromJsonBase64.isEmpty()) {
                    _metadataKeyForDecryption = QByteArray::fromBase64(QByteArray::fromBase64(lastMetadataKeyValueFromJsonBase64));
                }
            }
        }
    }

    if (metadataKeyForDecryption().isEmpty()) {
        qCDebug(lcCseMetadata()) << "Could not setup existing metadata with missing metadataKeys!";
        return;
    }

    if (metadataKeyForEncryption().isEmpty()) {
        _metadataKeyForEncryption = metadataKeyForDecryption();
    }

    const auto sharing = metadataObj["sharing"].toString().toLocal8Bit();
    const auto files = metaDataDoc.object()[filesKey].toObject();
    const auto metadataKey = metaDataDoc.object()[metadataJsonKey].toObject()[metadataKeyKey].toString().toUtf8();
    const auto metadataKeyChecksum = metaDataDoc.object()[metadataJsonKey].toObject()["checksum"].toString().toUtf8();

    _fileDrop = metaDataDoc.object().value("filedrop").toObject();
    // for unit tests
    _fileDropFromServer = metaDataDoc.object().value("filedrop").toObject();

    for (auto it = files.constBegin(); it != files.constEnd(); ++it) {
        EncryptedFile file;
        file.encryptedFilename = it.key();

        const auto fileObj = it.value().toObject();
        file.authenticationTag = QByteArray::fromBase64(fileObj["authenticationTag"].toString().toLocal8Bit());
        file.initializationVector = QByteArray::fromBase64(fileObj["initializationVector"].toString().toLocal8Bit());

        // Decrypt encrypted part
        const auto encryptedFile = fileObj[encryptedKey].toString().toLocal8Bit();
        const auto decryptedFile = decryptJsonObject(encryptedFile, metadataKeyForDecryption());
        const auto decryptedFileDoc = QJsonDocument::fromJson(decryptedFile);

        const auto decryptedFileObj = decryptedFileDoc.object();

        if (decryptedFileObj["filename"].toString().isEmpty()) {
            qCDebug(lcCseMetadata) << "decrypted metadata" << decryptedFileDoc.toJson(QJsonDocument::Indented);
            qCWarning(lcCseMetadata) << "skipping encrypted file" << file.encryptedFilename << "metadata has an empty file name";
            continue;
        }

        file.originalFilename = decryptedFileObj["filename"].toString();
        file.encryptionKey = QByteArray::fromBase64(decryptedFileObj["key"].toString().toLocal8Bit());
        file.mimetype = decryptedFileObj["mimetype"].toString().toLocal8Bit();

        // In case we wrongly stored "inode/directory" we try to recover from it
        if (file.mimetype == QByteArrayLiteral("inode/directory")) {
            file.mimetype = QByteArrayLiteral("httpd/unix-directory");
        }

        qCDebug(lcCseMetadata) << "encrypted file" << decryptedFileObj["filename"].toString() << decryptedFileObj["key"].toString() << it.key();

        _files.push_back(file);
    }

    if (!checkMetadataKeyChecksum(metadataKey, metadataKeyChecksum) && static_cast<int>(existingMetadataVersion() >= MetadataVersion::Version1_2)) {
        qCInfo(lcCseMetadata) << "checksum comparison failed"
                              << "server value" << metadataKeyChecksum << "client value" << computeMetadataKeyChecksum(metadataKey);
        if (!_account->shouldSkipE2eeMetadataChecksumValidation()) {
            qCDebug(lcCseMetadata) << "Failed to validate checksum for legacy metadata!";
            return;
        }
        qCDebug(lcCseMetadata) << "shouldSkipE2eeMetadataChecksumValidation is set. Allowing invalid checksum until next sync.";
    }
    _isMetadataValid = true;
}

void FolderMetadata::setupVersionFromExistingMetadata(const QByteArray &metadata)
{
    const auto doc = QJsonDocument::fromJson(metadata);
    const auto metaDataStr = metadataStringFromOCsDocument(doc);
    const auto metaDataDoc = QJsonDocument::fromJson(metaDataStr.toLocal8Bit());
    const auto metadataObj = metaDataDoc.object()[metadataJsonKey].toObject();

    QString versionStringFromMetadata;

    if (metadataObj.contains(versionKey)) {
        const auto metadataVersionValue = metadataObj.value(versionKey);
        if (metadataVersionValue.type() == QJsonValue::Type::String) {
            versionStringFromMetadata = metadataObj[versionKey].toString();
        } else if (metadataVersionValue.type() == QJsonValue::Type::Double) {
            versionStringFromMetadata = QString::number(metadataVersionValue.toDouble(), 'g', 2);
        }
    }
    else if (metaDataDoc.object().contains(versionKey)) {
        const auto metadataVersionValue = metaDataDoc.object()[versionKey].toVariant();
        if (metadataVersionValue.type() == QVariant::Type::String) {
            versionStringFromMetadata = metadataVersionValue.toString();
        } else if (metadataVersionValue.type() == QVariant::Type::Double) {
            versionStringFromMetadata = QString::number(metadataVersionValue.toDouble(), 'g', 2);
        } else if (metadataVersionValue.type() == QVariant::Type::Int) {
            versionStringFromMetadata = QString::number(metadataVersionValue.toInt()) + QStringLiteral(".0");
        }
    }

    if (versionStringFromMetadata == QStringLiteral("1.2")) {
        _existingMetadataVersion = MetadataVersion::Version1_2;
    } else if (versionStringFromMetadata == QStringLiteral("2.0") || versionStringFromMetadata == QStringLiteral("2")) {
        _existingMetadataVersion = MetadataVersion::Version2_0;
    } else if (versionStringFromMetadata == QStringLiteral("1.0") || versionStringFromMetadata == QStringLiteral("1")) {
        _existingMetadataVersion = MetadataVersion::Version1;
    }
}

void FolderMetadata::emitSetupComplete()
{
    QTimer::singleShot(0, this, [this]() {
        emit setupComplete();
    });
}

// RSA/ECB/OAEPWithSHA-256AndMGF1Padding using private / public key.
QByteArray FolderMetadata::encryptDataWithPublicKey(const QByteArray &data, const QSslKey key) const
{
    ClientSideEncryption::Bio publicKeyBio;
    const auto publicKeyPem = key.toPem();
    BIO_write(publicKeyBio, publicKeyPem.constData(), publicKeyPem.size());
    const auto publicKey = ClientSideEncryption::PKey::readPublicKey(publicKeyBio);

    // The metadata key is binary so base64 encode it first
    return EncryptionHelper::encryptStringAsymmetric(publicKey, data);
}

QByteArray FolderMetadata::decryptDataWithPrivateKey(const QByteArray &data) const
{
    ClientSideEncryption::Bio privateKeyBio;
    BIO_write(privateKeyBio, _account->e2e()->_privateKey.constData(), _account->e2e()->_privateKey.size());
    const auto privateKey = ClientSideEncryption::PKey::readPrivateKey(privateKeyBio);

    const auto decryptResult = EncryptionHelper::decryptStringAsymmetric(privateKey, data);
    if (decryptResult.isEmpty()) {
        qCDebug(lcCseMetadata()) << "ERROR. Could not decrypt the metadata key";
    }
    return decryptResult;
}

// AES/GCM/NoPadding (128 bit key size)
QByteArray FolderMetadata::encryptJsonObject(const QByteArray& obj, const QByteArray pass) const
{
    return EncryptionHelper::encryptStringSymmetric(pass, obj);
}

QByteArray FolderMetadata::decryptJsonObject(const QByteArray& encryptedMetadata, const QByteArray& pass) const
{
    return EncryptionHelper::decryptStringSymmetric(pass, encryptedMetadata);
}

bool FolderMetadata::checkMetadataKeyChecksum(const QByteArray &metadataKey, const QByteArray &metadataKeyChecksum) const
{
    const auto referenceMetadataKeyValue = computeMetadataKeyChecksum(metadataKey);

    return referenceMetadataKeyValue == metadataKeyChecksum;
}

QByteArray FolderMetadata::computeMetadataKeyChecksum(const QByteArray &metadataKey) const
{
    auto hashAlgorithm = QCryptographicHash{QCryptographicHash::Sha256};

    hashAlgorithm.addData(_account->e2e()->_mnemonic.remove(' ').toUtf8());
    auto sortedFiles = _files;
    std::sort(sortedFiles.begin(), sortedFiles.end(), [](const auto &first, const auto &second) {
        return first.encryptedFilename < second.encryptedFilename;
    });
    for (const auto &singleFile : sortedFiles) {
        hashAlgorithm.addData(singleFile.encryptedFilename.toUtf8());
    }
    hashAlgorithm.addData(metadataKey);

    return hashAlgorithm.result().toHex();
}

bool FolderMetadata::isValid() const
{
    return !metadataKeyForDecryption().isEmpty() || !_metadataKeys.isEmpty();
}

FolderMetadata::EncryptedFile FolderMetadata::parseEncryptedFileFromJson(const QString &encryptedFilename, const QJsonValue &fileJSON) const
{
    const auto fileObj = fileJSON.toObject();
    if (fileObj["filename"].toString().isEmpty()) {
        qCWarning(lcCseMetadata()) << "skipping encrypted file" << encryptedFilename << "metadata has an empty file name";
        return {};
    }
    
    EncryptedFile file;
    file.encryptedFilename = encryptedFilename;
    file.authenticationTag = QByteArray::fromBase64(fileObj[authenticationTagKey].toString().toLocal8Bit());
    file.initializationVector = QByteArray::fromBase64(fileObj[initializationVectorKey].toString().toLocal8Bit());
    file.originalFilename = fileObj["filename"].toString();
    file.encryptionKey = QByteArray::fromBase64(fileObj["key"].toString().toLocal8Bit());
    file.mimetype = fileObj["mimetype"].toString().toLocal8Bit();

    // In case we wrongly stored "inode/directory" we try to recover from it
    if (file.mimetype == QByteArrayLiteral("inode/directory")) {
        file.mimetype = QByteArrayLiteral("httpd/unix-directory");
    }

    return file;
}

QJsonObject FolderMetadata::convertFileToJsonObject(const EncryptedFile *encryptedFile, const QByteArray &metadataKey) const
{
    QJsonObject file;
    file.insert("key", QString(encryptedFile->encryptionKey.toBase64()));
    file.insert("filename", encryptedFile->originalFilename);
    file.insert("mimetype", QString(encryptedFile->mimetype));
    file.insert(initializationVectorKey, QString(encryptedFile->initializationVector.toBase64()));
    file.insert(authenticationTagKey, QString(encryptedFile->authenticationTag.toBase64()));

    return file;
}

const QByteArray FolderMetadata::metadataKeyForEncryption() const
{
    return _metadataKeyForEncryption;
}

const QSet<QByteArray>& FolderMetadata::keyChecksums() const
{
    return _keyChecksums;
}

void FolderMetadata::setupEmptyMetadata()
{
    if (_account->capabilities().clientSideEncryptionVersion() < 2.0) {
        return setupEmptyMetadataLegacy();
    }
    qCDebug(lcCseMetadata()) << "Setting up empty metadata v2";
    if (_isRootEncryptedFolder) {
        addUser(_account->davUser(), _account->e2e()->_certificate);
        _metadataKeyForDecryption = _metadataKeyForEncryption;
    }
    _isMetadataValid = true;

    emitSetupComplete();
}

void FolderMetadata::setupEmptyMetadataLegacy()
{
    qCDebug(lcCseMetadata) << "Settint up legacy empty metadata";
    _metadataKeyForEncryption = EncryptionHelper::generateRandom(metadataKeySize);
    _metadataKeyForDecryption = _metadataKeyForEncryption;
    QString publicKey = _account->e2e()->_publicKey.toPem().toBase64();
    QString displayName = _account->displayName();

    _sharing.append({displayName, publicKey});

    _isMetadataValid = true;

    emitSetupComplete();
}

QByteArray FolderMetadata::encryptedMetadata()
{
    Q_ASSERT(_isMetadataValid);
    if (!_isMetadataValid) {
        qCCritical(lcCseMetadata()) << "Could not encrypt non-initialized metadata!";
        return {};
    }

    if (latestSupportedMetadataVersion(_account->capabilities().clientSideEncryptionVersion()) < MetadataVersion::Version2_0) {
        return encryptedMetadataLegacy();
    }

    qCDebug(lcCseMetadata()) << "Encrypting metadata for latest version"
                             << latestSupportedMetadataVersion(_account->capabilities().clientSideEncryptionVersion());
    if (_isRootEncryptedFolder && _folderUsers.isEmpty() && existingMetadataVersion() < MetadataVersion::Version2_0) {
        // migrated from legacy version, create metadata key and setup folderUsrs array
        createNewMetadataKeyForEncryption();
    }

    if (metadataKeyForEncryption().isEmpty()) {
        qCDebug(lcCseMetadata()) << "Encrypting metadata failed! Empty metadata key!";
        return {};
    }

    QJsonObject files, folders;
    for (auto it = _files.constBegin(), end = _files.constEnd(); it != end; ++it) {
        const auto file = convertFileToJsonObject(it, _metadataKeyForEncryption);
        if (file.isEmpty()) {
            qCDebug(lcCseMetadata) << "Metadata generation failed for file" << it->encryptedFilename;
            return {};
        }
        const auto isDirectory =
            it->mimetype.isEmpty() || it->mimetype == QByteArrayLiteral("inode/directory") || it->mimetype == QByteArrayLiteral("httpd/unix-directory");
        if (isDirectory) {
            folders.insert(it->encryptedFilename, it->originalFilename);
        } else {
            files.insert(it->encryptedFilename, file);
        }
    }

    QJsonArray keyChecksums;
    if (_isRootEncryptedFolder) {
        for (auto it = _keyChecksums.constBegin(), end = _keyChecksums.constEnd(); it != end; ++it) {
            keyChecksums.push_back(QJsonValue::fromVariant(*it));
        }
    }

    QJsonObject cipherText = {{filesKey, files}, {foldersKey, folders}};

    const auto isChecksumsArrayValid = (!_isRootEncryptedFolder && keyChecksums.isEmpty()) || (_isRootEncryptedFolder && !keyChecksums.isEmpty());
    Q_ASSERT(isChecksumsArrayValid);
    if (!isChecksumsArrayValid) {
        qCDebug(lcCseMetadata) << "Empty keyChecksums while shouldn't be empty!";
        return {};
    }
    if (!keyChecksums.isEmpty()) {
        cipherText.insert(keyChecksumsKey, keyChecksums);
    }

    const QJsonDocument cipherTextDoc(cipherText);

    QByteArray authenticationTag;
    const auto initializationVector = EncryptionHelper::generateRandom(metadataKeySize);
    const auto encryptedCipherText = EncryptionHelper::gZipThenEncryptData(metadataKeyForEncryption(), cipherTextDoc.toJson(QJsonDocument::Compact), initializationVector, authenticationTag).toBase64();
    const QJsonObject metadata{{cipherTextKey, QJsonValue::fromVariant(encryptedCipherText)},
                               {nonceKey, QJsonValue::fromVariant(initializationVector.toBase64())},
                               {authenticationTagKey, QJsonValue::fromVariant(authenticationTag.toBase64())}};

    const auto metadataVersionFromApi = _account->capabilities().clientSideEncryptionVersion();
    QJsonObject metaObject = {{metadataJsonKey, metadata}, {versionKey, QString::number(_account->capabilities().clientSideEncryptionVersion(), 'g', 2)}};

    QJsonArray folderUsers;
    if (_isRootEncryptedFolder) {
        for (auto it = _folderUsers.constBegin(), end = _folderUsers.constEnd(); it != end; ++it) {
            const auto folderUser = it.value();

            const QJsonObject folderUserJson{{usersUserIdKey, folderUser.userId},
                                             {usersCertificateKey, QJsonValue::fromVariant(folderUser.certificatePem)},
                                             {usersEncryptedMetadataKey, QJsonValue::fromVariant(folderUser.encryptedMetadataKey.toBase64())},
                                             {usersEncryptedFiledropKey, QJsonValue::fromVariant(folderUser.encryptedFiledropKey.toBase64())}};
            folderUsers.push_back(folderUserJson);
        }
    }
    const auto isFolderUsersArrayValid = (!_isRootEncryptedFolder && folderUsers.isEmpty()) || (_isRootEncryptedFolder && !folderUsers.isEmpty());
    Q_ASSERT(isFolderUsersArrayValid);
    if (!isFolderUsersArrayValid) {
        qCCritical(lcCseMetadata) << "Empty folderUsers while shouldn't be empty!";
        return {};
    }

    if (!folderUsers.isEmpty()) {
        metaObject.insert(usersKey, folderUsers);
    }

    if (!_fileDropCipherTextEncryptedAndBase64.isEmpty()) {
        const QJsonObject fileDropMetadata{{cipherTextKey, QJsonValue::fromVariant(_fileDropCipherTextEncryptedAndBase64)},
                                           {nonceKey, QJsonValue::fromVariant(_fileDropMetadataNonceBase64)},
                                           {authenticationTagKey, QJsonValue::fromVariant(_fileDropMetadataAuthenticationTag.toBase64())}};
        metaObject.insert(filedropKey, fileDropMetadata);
    }

    QJsonDocument internalMetadata;
    internalMetadata.setObject(metaObject);

    auto jsonString = internalMetadata.toJson();

    _encryptedMetadataVersion = latestSupportedMetadataVersion(metadataVersionFromApi);

    return internalMetadata.toJson();
}

QByteArray FolderMetadata::encryptedMetadataLegacy()
{
    qCDebug(lcCseMetadata) << "Generating metadata";

    if (_metadataKeyForEncryption.isEmpty()) {
        qCDebug(lcCseMetadata) << "Metadata generation failed! Empty metadata key!";
        return {};
    }
    const auto version = _account->capabilities().clientSideEncryptionVersion();
    // multiple toBase64() just to keep with the old (wrong way)
    const auto encryptedMetadataKey = encryptDataWithPublicKey(_metadataKeyForEncryption.toBase64().toBase64(), _account->e2e()->_publicKey).toBase64();
    const QJsonObject metadata{
        {versionKey, QString::number(version, 'g', 2)},
        {metadataKeyKey, QJsonValue::fromVariant(encryptedMetadataKey)},
        {"checksum", QJsonValue::fromVariant(computeMetadataKeyChecksum(encryptedMetadataKey))},
    };

    QJsonObject files;
    for (auto it = _files.constBegin(), end = _files.constEnd(); it != end; ++it) {
        QJsonObject encrypted;
        encrypted.insert("key", QString(it->encryptionKey.toBase64()));
        encrypted.insert("filename", it->originalFilename);
        encrypted.insert("mimetype", QString(it->mimetype));
        QJsonDocument encryptedDoc;
        encryptedDoc.setObject(encrypted);

        QString encryptedEncrypted = encryptJsonObject(encryptedDoc.toJson(QJsonDocument::Compact), _metadataKeyForEncryption);
        if (encryptedEncrypted.isEmpty()) {
            qCDebug(lcCseMetadata) << "Metadata generation failed!";
        }
        QJsonObject file;
        file.insert(encryptedKey, encryptedEncrypted);
        file.insert(initializationVectorKey, QString(it->initializationVector.toBase64()));
        file.insert(authenticationTagKey, QString(it->authenticationTag.toBase64()));

        files.insert(it->encryptedFilename, file);
    }

    QJsonObject filedrop;
    for (auto fileDropIt = _fileDrop.constBegin(), end = _fileDrop.constEnd(); fileDropIt != end; ++fileDropIt) {
        filedrop.insert(fileDropIt.key(), fileDropIt.value());
    }

    auto metaObject = QJsonObject{
        {metadataJsonKey, metadata},
    };

    if (files.count()) {
        metaObject.insert(filesKey, files);
    }

    if (filedrop.count()) {
        metaObject.insert(filedropKey, filedrop);
    }

    _encryptedMetadataVersion = latestSupportedMetadataVersion(version);

    QJsonDocument internalMetadata;
    internalMetadata.setObject(metaObject);
    return internalMetadata.toJson();
}

FolderMetadata::MetadataVersion FolderMetadata::existingMetadataVersion() const
{
    return _existingMetadataVersion;
}

FolderMetadata::MetadataVersion FolderMetadata::encryptedMetadataVersion() const
{
    return _encryptedMetadataVersion;
}

bool FolderMetadata::isVersion2AndUp() const
{
    return existingMetadataVersion() >= MetadataVersion::Version2_0;
}

FolderMetadata::MetadataVersion FolderMetadata::latestSupportedMetadataVersion(const double versionFromApi)
{
    if (versionFromApi >= 2.0) {
        return MetadataVersion::Version2_0;
    } else if (versionFromApi >= 1.2) {
        return MetadataVersion::Version1_2;
    } else if (versionFromApi >= 1.0) {
        return MetadataVersion::Version1;
    } else {
        return MetadataVersion::VersionUndefined;
    }
}

EncryptionStatusEnums::ItemEncryptionStatus FolderMetadata::fromMedataVersionToItemEncryptionStatus(const MetadataVersion &metadataVersion)
{
    switch (metadataVersion) {
    case FolderMetadata::MetadataVersion::Version2_0:
        return SyncFileItem::EncryptionStatus::EncryptedMigratedV2_0;
    case FolderMetadata::MetadataVersion::Version1_2:
        return SyncFileItem::EncryptionStatus::EncryptedMigratedV1_2;
    case FolderMetadata::MetadataVersion::Version1:
        return SyncFileItem::EncryptionStatus::Encrypted;
    }
    return SyncFileItem::EncryptionStatus::NotEncrypted;
}

void FolderMetadata::addEncryptedFile(const EncryptedFile &f) {
    Q_ASSERT(_isMetadataValid);
    if (!_isMetadataValid) {
        qCCritical(lcCseMetadata()) << "Could not add encrypted file to non-initialized metadata!";
        return;
    }

    for (int i = 0; i < _files.size(); ++i) {
        if (_files.at(i).originalFilename == f.originalFilename) {
            _files.removeAt(i);
            break;
        }
    }

    _files.append(f);
}

const QByteArray FolderMetadata::metadataKeyForDecryption() const
{
    return _metadataKeyForDecryption;
}

void FolderMetadata::removeEncryptedFile(const EncryptedFile &f)
{
    for (int i = 0; i < _files.size(); ++i) {
        if (_files.at(i).originalFilename == f.originalFilename) {
            _files.removeAt(i);
            break;
        }
    }
}

void FolderMetadata::removeAllEncryptedFiles()
{
    _files.clear();
}

QVector<FolderMetadata::EncryptedFile> FolderMetadata::files() const
{
    return _files;
}

bool FolderMetadata::isFileDropPresent() const
{
    return !_fileDropCipherTextEncryptedAndBase64.isEmpty();
}

bool FolderMetadata::encryptedMetadataNeedUpdate() const
{
    return latestSupportedMetadataVersion(_account->capabilities().clientSideEncryptionVersion()) > existingMetadataVersion();
}

bool FolderMetadata::moveFromFileDropToFiles()
{
    if (_fileDropCipherTextEncryptedAndBase64.isEmpty() || _metadataKeyForEncryption.isEmpty() || _metadataNonce.isEmpty()) {
        return false;
    }

    const auto cipherTextDecrypted = EncryptionHelper::decryptThenUnGzipData(_metadataKeyForEncryption, QByteArray::fromBase64(_fileDropCipherTextEncryptedAndBase64), _metadataNonce);
    const auto cipherTextDocument = QJsonDocument::fromJson(cipherTextDecrypted);

    const auto files = cipherTextDocument.object()[filesKey].toObject();
    const auto folders = cipherTextDocument.object()[foldersKey].toObject();

    for (auto it = files.constBegin(); it != files.constEnd(); ++it) {
        const auto parsedEncryptedFile = parseEncryptedFileFromJson(it.key(), it.value());
        if (!parsedEncryptedFile.originalFilename.isEmpty()) {
            _files.push_back(parsedEncryptedFile);
        }
    }

    for (auto it = folders.constBegin(); it != folders.constEnd(); ++it) {
        const auto folderName = it.value().toString();
        if (!folderName.isEmpty()) {
            EncryptedFile file;
            file.encryptedFilename = it.key();
            file.originalFilename = folderName;
        }
    }

    _fileDropCipherTextEncryptedAndBase64.clear();

    return true;
}

const QByteArray &FolderMetadata::fileDrop() const
{
    return _fileDropCipherTextEncryptedAndBase64;
}

void FolderMetadata::startFetchRootE2eeFolderMetadata(const QString &path)
{
    const auto job = new LsColJob(_account, path, this);
    job->setProperties({"resourcetype", "http://owncloud.org/ns:fileid"});
    connect(job, &LsColJob::directoryListingSubfolders, this, &FolderMetadata::rootE2eeFolderEncryptedIdReceived);
    connect(job, &LsColJob::finishedWithError, this, &FolderMetadata::rootE2eeFolderEncryptedIdError);
    job->start();
}

void FolderMetadata::fetchRootE2eeFolderMetadata(const QByteArray &folderId)
{
    const auto getMetadataJob = new GetMetadataApiJob(_account, folderId);
    connect(getMetadataJob, &GetMetadataApiJob::jsonReceived, this, &FolderMetadata::rootE2eeFolderMetadataReceived);
    connect(getMetadataJob, &GetMetadataApiJob::error, this, &FolderMetadata::rotE2eeFolderEncryptedMetadataError);
    getMetadataJob->start();
}

void FolderMetadata::rootE2eeFolderEncryptedIdReceived(const QStringList &list)
{
    const auto job = qobject_cast<LsColJob *>(sender());
    Q_ASSERT(job);
    if (!job || job->_folderInfos.isEmpty()) {
        rootE2eeFolderMetadataReceived({}, 404);
        return;
    }
    fetchRootE2eeFolderMetadata(job->_folderInfos.value(list.first()).fileId);
}

void FolderMetadata::rotE2eeFolderEncryptedMetadataError(const QByteArray &fileId, int httpReturnCode)
{
    Q_UNUSED(fileId);
    Q_UNUSED(httpReturnCode);
    rootE2eeFolderMetadataReceived({}, httpReturnCode);
}

void FolderMetadata::rootE2eeFolderMetadataReceived(const QJsonDocument &json, int statusCode)
{
    if (json.isEmpty()) {
        setupMetadata();
        return;
    }

    QSharedPointer<FolderMetadata> rootE2eeFolderMetadata(new FolderMetadata(_account, json.toJson(QJsonDocument::Compact), RootEncryptedFolderInfo::makeDefault()));
    connect(rootE2eeFolderMetadata.data(), &FolderMetadata::setupComplete, this, [this, rootE2eeFolderMetadata]() {
        if (!rootE2eeFolderMetadata->isValid() || !rootE2eeFolderMetadata->isVersion2AndUp()) {
            setupMetadata();
            return;
        }

        _metadataKeyForEncryption = rootE2eeFolderMetadata->metadataKeyForEncryption();

        if (!isVersion2AndUp()) {
            setupMetadata();
            return;
        }
        _metadataKeyForDecryption = rootE2eeFolderMetadata->metadataKeyForDecryption();
        _metadataKeyForEncryption = rootE2eeFolderMetadata->metadataKeyForEncryption();
        _keyChecksums = rootE2eeFolderMetadata->keyChecksums();
        setupMetadata();
    });
}

void FolderMetadata::rootE2eeFolderEncryptedIdError(QNetworkReply *reply)
{
    rootE2eeFolderMetadataReceived({}, reply ? reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() : 0);
}

bool FolderMetadata::addUser(const QString &userId, const QSslCertificate &certificate)
{
    Q_ASSERT(_isRootEncryptedFolder);
    if (!_isRootEncryptedFolder) {
        qCWarning(lcCseMetadata()) << "Could not add a folder user to a non top level folder.";
        return false;
    }

    const auto certificatePublicKey = certificate.publicKey();
    if (userId.isEmpty() || certificate.isNull() || certificatePublicKey.isNull()) {
        qCWarning(lcCseMetadata()) << "Could not add a folder user. Invalid userId or certificate.";
        return false;
    }

    createNewMetadataKeyForEncryption();
    FolderUser newFolderUser;
    newFolderUser.userId = userId;
    newFolderUser.certificatePem = certificate.toPem();
    newFolderUser.encryptedMetadataKey = encryptDataWithPublicKey(_metadataKeyForEncryption, certificatePublicKey);
    _folderUsers[userId] = newFolderUser;
    updateUsersEncryptedMetadataKey();

    return true;
}

bool FolderMetadata::removeUser(const QString &userId)
{
    Q_ASSERT(_isRootEncryptedFolder);
    if (!_isRootEncryptedFolder) {
        qCWarning(lcCseMetadata()) << "Could not add remove folder user from a non top level folder.";
        return false;
    }
    Q_ASSERT(!userId.isEmpty());
    if (userId.isEmpty()) {
        qCDebug(lcCseMetadata()) << "Could not remove a folder user. Invalid userId.";
        return false;
    }

    createNewMetadataKeyForEncryption();
    _folderUsers.remove(userId);
    updateUsersEncryptedMetadataKey();

    return true;
}

void FolderMetadata::setMetadataKeyForDecryption(const QByteArray &metadataKeyForDecryption)
{
    _metadataKeyForDecryption = metadataKeyForDecryption;
}

void FolderMetadata::setMetadataKeyForEncryption(const QByteArray &metadataKeyForDecryption)
{
    _metadataKeyForEncryption = metadataKeyForDecryption;
}

void FolderMetadata::setKeyChecksums(const QSet<QByteArray> &keyChecksums)
{
    _keyChecksums = keyChecksums;
}

void FolderMetadata::updateUsersEncryptedMetadataKey()
{
    Q_ASSERT(_isRootEncryptedFolder);
    if (!_isRootEncryptedFolder) {
        qCWarning(lcCseMetadata()) << "Could not update folder users in a non top level folder.";
        return;
    }
    Q_ASSERT(!_metadataKeyForEncryption.isEmpty());
    if (_metadataKeyForEncryption.isEmpty()) {
        qCWarning(lcCseMetadata()) << "Could not update folder users with empty metadataKey!";
        return;
    }
    for (auto it = _folderUsers.constBegin(); it != _folderUsers.constEnd(); ++it) {
        auto folderUser = it.value();

        const QSslCertificate certificate(folderUser.certificatePem);
        const auto certificatePublicKey = certificate.publicKey();
        if (certificate.isNull() || certificatePublicKey.isNull()) {
            qCWarning(lcCseMetadata()) << "Could not update folder users with null certificatePublicKey!";
            continue;
        }

        const auto encryptedMetadataKey = encryptDataWithPublicKey(_metadataKeyForEncryption, certificatePublicKey);
        if (encryptedMetadataKey.isEmpty()) {
            qCWarning(lcCseMetadata()) << "Could not update folder users with empty encryptedMetadataKey!";
            continue;
        }

        folderUser.encryptedMetadataKey = encryptedMetadataKey;

        _folderUsers[it.key()] = folderUser;
    }
}

void FolderMetadata::createNewMetadataKeyForEncryption()
{
    if (!_isRootEncryptedFolder) {
        return;
    }
    if (!_metadataKeyForEncryption.isEmpty()) {
        _keyChecksums.remove(calcSha256(_metadataKeyForEncryption));
    }
    _metadataKeyForEncryption = EncryptionHelper::generateRandom(metadataKeySize);
    if (!_metadataKeyForEncryption.isEmpty()) {
        _keyChecksums.insert(calcSha256(_metadataKeyForEncryption));
    }
}

bool FolderMetadata::verifyMetadataKey(const QByteArray &metadataKey) const
{
    if (existingMetadataVersion() < MetadataVersion::Version2_0) {
        return true;
    }
    if (metadataKey.isEmpty() || metadataKey.size() < metadataKeySize ) {
        return false;
    }
    const QByteArray metadataKeyLimitedLength(metadataKey.data(), metadataKeySize );
    // _keyChecksums should not be empty, fix this by taking a proper _keyChecksums from the topLevelFolder
    return _keyChecksums.contains(calcSha256(metadataKeyLimitedLength)) || _keyChecksums.isEmpty();
}
}
