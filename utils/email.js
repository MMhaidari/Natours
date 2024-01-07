const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
        const transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: process.env.EMAIL_PORT,
            auth: {
                user: process.env.EMAIL_USERNAME,
                pass: process.env.EMAIL_PASSWORD,
            },
        });

        // Define the email options
        const mailOptions = {
            from: 'Mohammad Mohsen <mohsenhaidari@gmail.com>',
            to: options.email,
            subject: options.subject,
            text: options.message,
        };

        // Send the email
        await transporter.sendMail(mailOptions);
        console.log('Email sent successfully.');
};

module.exports = sendEmail;
