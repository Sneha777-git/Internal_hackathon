const express = require('express');
const cors = require('cors');
require('dotenv').config();

const decodeRoute = require('./routes/decode');

const app = express();
app.use(cors());
app.use(express.json());

app.use('/decode', decodeRoute);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
