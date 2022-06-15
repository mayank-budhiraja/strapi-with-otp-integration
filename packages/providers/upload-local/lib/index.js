'use strict';

/**
 * Module dependencies
 */

// Public node modules.
const { pipeline } = require('stream');
const fs = require('fs');
const path = require('path');
const fse = require('fs-extra');
const { PayloadTooLargeError } = require('@strapi/utils').errors;

const UPLOADS_FOLDER_NAME = 'uploads';

module.exports = {
  init({ sizeLimit = 1000000 } = {}) {
    const verifySize = file => {
      if (file.size > sizeLimit) {
        throw new PayloadTooLargeError();
      }
    };

    // Ensure uploads folder exists
    const uploadPath = path.resolve(strapi.dirs.public, UPLOADS_FOLDER_NAME);
    if (!fse.pathExistsSync(uploadPath)) {
      throw new Error(
        `The upload folder (${uploadPath}) doesn't exist or is not accessible. Please make sure it exists.`
      );
    }

    return {
      uploadStream(file) {
        verifySize(file);

        return new Promise((resolve, reject) => {
          pipeline(
            file.stream,
            fs.createWriteStream(path.join(uploadPath, `${file.hash}${file.ext}`)),
            err => {
              if (err) {
                return reject(err);
              }

              file.url = `/uploads/${file.hash}${file.ext}`;

              resolve();
            }
          );
        });
      },
      upload(file) {
        verifySize(file);

        return new Promise((resolve, reject) => {
          // write file in public/assets folder
          fs.writeFile(path.join(uploadPath, `${file.hash}${file.ext}`), file.buffer, err => {
            if (err) {
              return reject(err);
            }

            file.url = `/${UPLOADS_FOLDER_NAME}/${file.hash}${file.ext}`;

            resolve();
          });
        });
      },
      delete(file) {
        return new Promise((resolve, reject) => {
          const filePath = path.join(uploadPath, `${file.hash}${file.ext}`);

          if (!fs.existsSync(filePath)) {
            return resolve("File doesn't exist");
          }

          // remove file from public/assets folder
          fs.unlink(filePath, err => {
            if (err) {
              return reject(err);
            }

            resolve();
          });
        });
      },
    };
  },
};
