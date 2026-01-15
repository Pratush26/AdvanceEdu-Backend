import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import Stripe from "stripe";

dotenv.config();
const app = express();
const port = process.env.PORT || 8000;
const uri = process.env.DB;
const allowedOrigins = process.env.FRONTENDS.split(",");

app.use(cors({
    origin: allowedOrigins ? allowedOrigins : ['http://localhost:5173']
}));
app.use(express.json());

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

//  listeners
client.connect()
    .then(() => app.listen(port, () => console.log(`Server listening ${port} and successfully connected with DB.`)))
    .catch((err) => console.log(err))

//  DB & collections
const database = client.db("e-com");

//  Middleware

//  Public Api
app.get("/", async (req, res) => res.send("Server is getting!"))