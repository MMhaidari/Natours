const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config({ path: './config.env' });
const app = require('./app');

const DB = "mongodb+srv://mohsenhaidari0766:admin123@cluster0.n1zbq4y.mongodb.net/natoursPractice?retryWrites=true&w=majority";

mongoose
  .connect(DB)
  .then(() => console.log('DB connection successful!'))
  .catch((error) => {
    console.log(error);
  });


const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
  console.log(`App running on port ${port}...`);
});