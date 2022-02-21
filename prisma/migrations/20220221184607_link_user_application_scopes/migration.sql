/*
  Warnings:

  - Added the required column `scopeId` to the `UserApplicationScopes` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE `UserApplicationScopes` ADD COLUMN `scopeId` INTEGER NOT NULL;

-- AddForeignKey
ALTER TABLE `UserApplicationScopes` ADD CONSTRAINT `UserApplicationScopes_scopeId_fkey` FOREIGN KEY (`scopeId`) REFERENCES `ApplicationScopes`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
