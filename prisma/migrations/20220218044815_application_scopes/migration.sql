-- AlterTable
ALTER TABLE `Application` ADD COLUMN `inviteOnly` BOOLEAN NOT NULL DEFAULT true;

-- AlterTable
ALTER TABLE `User` ADD COLUMN `address` VARCHAR(191) NULL,
    ADD COLUMN `address2` VARCHAR(191) NULL,
    ADD COLUMN `avatar` VARCHAR(191) NULL,
    ADD COLUMN `city` VARCHAR(191) NULL,
    ADD COLUMN `phone` VARCHAR(191) NULL,
    ADD COLUMN `state` VARCHAR(2) NULL,
    ADD COLUMN `zip` INTEGER NULL;

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
CREATE TABLE `UserApplicationScopes` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `uuid` VARCHAR(191) NOT NULL,
    `clientId` VARCHAR(191) NOT NULL,
    `status` BOOLEAN NOT NULL DEFAULT false,
    `updatedAt` DATETIME(3) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `ApplicationScopes` ADD CONSTRAINT `ApplicationScopes_clientId_fkey` FOREIGN KEY (`clientId`) REFERENCES `Application`(`clientId`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `UserApplicationScopes` ADD CONSTRAINT `UserApplicationScopes_uuid_fkey` FOREIGN KEY (`uuid`) REFERENCES `User`(`uuid`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `UserApplicationScopes` ADD CONSTRAINT `UserApplicationScopes_clientId_fkey` FOREIGN KEY (`clientId`) REFERENCES `Application`(`clientId`) ON DELETE RESTRICT ON UPDATE CASCADE;
