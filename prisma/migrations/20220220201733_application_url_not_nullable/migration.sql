/*
  Warnings:

  - Made the column `applicationUrl` on table `Application` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE `Application` MODIFY `applicationUrl` VARCHAR(191) NOT NULL DEFAULT 'http://localhost:3000';
