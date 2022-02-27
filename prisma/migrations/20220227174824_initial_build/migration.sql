-- CreateTable
CREATE TABLE `User` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `oid` VARCHAR(191) NOT NULL,
    `email` VARCHAR(191) NOT NULL,
    `password` VARCHAR(191) NOT NULL,
    `firstName` VARCHAR(191) NULL,
    `lastName` VARCHAR(191) NULL,
    `phone` VARCHAR(191) NULL,
    `address` VARCHAR(191) NULL,
    `address2` VARCHAR(191) NULL,
    `city` VARCHAR(191) NULL,
    `state` VARCHAR(2) NULL,
    `zip` INTEGER NULL,
    `birthday` DATETIME(3) NULL,
    `avatar` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `lastAccess` DATETIME(3) NOT NULL,
    `active` BOOLEAN NOT NULL DEFAULT true,

    UNIQUE INDEX `User_oid_key`(`oid`),
    UNIQUE INDEX `User_email_key`(`email`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Application` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `clientId` VARCHAR(191) NOT NULL,
    `objectId` VARCHAR(191) NOT NULL,
    `applicationSecret` VARCHAR(191) NOT NULL,
    `ownerId` VARCHAR(191) NOT NULL,
    `displayName` VARCHAR(191) NOT NULL,
    `description` VARCHAR(191) NULL,
    `inviteOnly` BOOLEAN NOT NULL DEFAULT true,
    `applicationUrl` VARCHAR(191) NOT NULL DEFAULT 'http://localhost:3000',
    `termsOfServiceUrl` VARCHAR(191) NULL,
    `privacyStatementUrl` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `active` BOOLEAN NOT NULL DEFAULT true,

    UNIQUE INDEX `Application_clientId_key`(`clientId`),
    UNIQUE INDEX `Application_objectId_key`(`objectId`),
    UNIQUE INDEX `Application_applicationSecret_key`(`applicationSecret`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ApplicationScopes` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `clientId` VARCHAR(191) NOT NULL,
    `scope` ENUM('email_read', 'email_readwrite', 'email_notify', 'name_read', 'name_readwrite', 'phone_read', 'phone_readwrite', 'phone_notify', 'address_read', 'address_readwrite', 'address_notify', 'birthday_read', 'birthday_readwrite', 'profile_read', 'profile_readwrite') NOT NULL,
    `required` BOOLEAN NOT NULL DEFAULT false,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ApplicationScopeInfo` (
    `scope` ENUM('email_read', 'email_readwrite', 'email_notify', 'name_read', 'name_readwrite', 'phone_read', 'phone_readwrite', 'phone_notify', 'address_read', 'address_readwrite', 'address_notify', 'birthday_read', 'birthday_readwrite', 'profile_read', 'profile_readwrite') NOT NULL,
    `summary` VARCHAR(300) NOT NULL,
    `description` VARCHAR(2000) NOT NULL,

    PRIMARY KEY (`scope`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `UserApplicationScopes` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `oid` VARCHAR(191) NOT NULL,
    `clientId` VARCHAR(191) NOT NULL,
    `scopeId` INTEGER NOT NULL,
    `status` BOOLEAN NOT NULL DEFAULT false,
    `updatedAt` DATETIME(3) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `Application` ADD CONSTRAINT `Application_ownerId_fkey` FOREIGN KEY (`ownerId`) REFERENCES `User`(`oid`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ApplicationScopes` ADD CONSTRAINT `ApplicationScopes_clientId_fkey` FOREIGN KEY (`clientId`) REFERENCES `Application`(`clientId`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ApplicationScopes` ADD CONSTRAINT `ApplicationScopes_scope_fkey` FOREIGN KEY (`scope`) REFERENCES `ApplicationScopeInfo`(`scope`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `UserApplicationScopes` ADD CONSTRAINT `UserApplicationScopes_oid_fkey` FOREIGN KEY (`oid`) REFERENCES `User`(`oid`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `UserApplicationScopes` ADD CONSTRAINT `UserApplicationScopes_clientId_fkey` FOREIGN KEY (`clientId`) REFERENCES `Application`(`clientId`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `UserApplicationScopes` ADD CONSTRAINT `UserApplicationScopes_scopeId_fkey` FOREIGN KEY (`scopeId`) REFERENCES `ApplicationScopes`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
