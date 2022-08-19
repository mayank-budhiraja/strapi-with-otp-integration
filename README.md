# Strapi with OTP Integration

I haven't forked this project, this is just for the demo on how the OTP can be integrated to the strapi. Also we are using only OTP integration in this project. I have created a sample project "Staax-backend" to help in understanding for the developers.

# Setup

    - Add the user-schema to extension folder

    - In settings, allow access to verifyOTP api

    - Optional, For a new project
        yarn create strapi-app my-project --quickstart

    - Authenticated calls through JWT Token

    - yarn setup && cd ./main/staax-backend && yarn develop

# Extend your Strapi

    - Main changes for OTP integration lies under this file
        - packages/plugins/users-permissions/server/controllers/auth.js
