import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken'
import Stripe from "stripe";

dotenv.config();

const app = express();
const port = process.env.PORT || 8000;
const uri = process.env.DB;
const JWT_SECRET = process.env.JWT_SECRET;
const allowedOrigins = process.env.FRONTENDS.split(",");

app.use(cors({
  origin: allowedOrigins ? allowedOrigins : ['http://localhost:5173']
}));
app.use(express.json());

//  DB & collections
if (!uri) throw new Error("Missing DB env var");

const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

let db;
async function getDB() {
  if (!db) {
    await client.connect();
    db = client.db("e-com");
  }
  return db;
}

//  Middleware
export function verifyUser(req, res, next) {
  try {
    const token = req.cookies?.token;
    if (!token) return res.status(401).json({ message: "Unauthorized: No token" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; 
    next();
  } catch (err) {
    return res.status(401).json({ message: "Unauthorized: Invalid or expired token" });
  }
}

export function requireRole(role) {
  return (req, res, next) => {
    if (role.include(req.user.role)) return res.status(403).json({ message: "Forbidden: Insufficient role" });
    next();
  };
}

//  Public Api
app.get("/", async (req, res) => res.send("Server is getting!"))
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password are required" });

    const db = await getDB()
    const user = await db.collection("users").findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(403).json({ message: "Invalid email or password" });

    const token = jwt.sign(
      { id: user._id.toString(), email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      path: "/",
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 1000 * 60 * 60 * 24,
    });

    return res.status(200).json({
      message: "Login successful",
      user: {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("user login error", err);
    return res.status(500).json({ message: "Internal Server Error!" });
  }
});
app.post("/register", async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;
    if (!email || !password || !name || !phone) return res.status(400).json({ message: "credentials missing" });

    const db = await getDB()
    const exists = await db.collection("users").findOne({ email });
    if (!!exists) return res.status(409).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(String(password), 10);
    const user = await db.collection("users").insertOne({ email, password: hashedPassword, name, phone, role: "user", premium: false, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });

    return res.status(200).json(user);
  } catch (err) {
    console.error("user login error", err);
    return res.status(500).json({ message: "Internal Server Error!" });
  }
});
app.post("/item", async (req, res) => {
  try {
    const { name, description, photo, price, quantity } = req.body;
    if (!price || !name) return res.status(400).json({ message: "credentials missing" });

    const db = await getDB()
    const item = await db.collection("items").insertOne({ name, description, photo, price, quantity, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });

    return res.status(200).json(item);
  } catch (err) {
    console.error("user login error", err);
    return res.status(500).json({ message: "Internal Server Error!" });
  }
});

app.post("/checkout-session", verifyUser, async (req, res) => {
    try {
        const db = await getDB()
        const user = await db.collection("users").findOne({ email: req?.user?.email }, { projection: { premium: 1 } });
        if(!user) return res.status(401).json({ message: "Unauthorized Access"});

        const item = await db.collection("items").findOne({ _id: new ObjectId(req.body?.id) });
        if (!item) return res.send({ url: "" })

        const origin = req.headers.origin;
        const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
        const session = await stripe.checkout.sessions.create({
            line_items: [
                {
                    price_data: {
                        currency: "BDT",
                        unit_amount: 100 * 100,
                        product_data: {
                            name: item.name
                        }
                    },
                    quantity: req.body?.quantity ?? 1,
                },
            ],
            customer_email: req?.user?.email,
            metadata: {
                itemId: req.body?.id,
                photo: item.photo
            },
            mode: 'payment',
            success_url: `${origin}/after-payment?success=true&type=boost&session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${origin}/after-payment?success=false&type=boost`,
        });
        res.send({ success: true, url: session.url });
    } catch (error) {
        console.error(error)
        res.send({ success: false, message: "Something went wrong!", url: "" })
    }
})

app.listen(port, () => console.log(`Server listening on Port - ${port}`))