import express from "express";
import cors from "cors";
import { MongoClient } from "mongodb";
import dotenv from "dotenv";
// import { router } from "./routes/index.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
// app.use(router);
const PORT = process.env.PORT || 5000;

const client = new MongoClient(process.env.MONGODB_URI);
export async function connectToDatabase() {
  try {
    await client.connect();
    return client;
  } catch (error) {
    console.error("Error connecting to database:", error);
  }
}

const connectedClient = await connectToDatabase();

const db = connectedClient.db("gear-nest");
const usersCollection = db.collection("user");
const equipmentCollection = db.collection("equipment");

app.get("/", (req, res) => {
  res.send("Server is running");
});

app.get("/users", async (req, res) => {
  const result = await usersCollection.find({}).toArray();
  res.send(result);
});

app.post("/equipment", async (req, res) => {
  const equipment = {
    ...req.body,
    status: "pending",
    createdAt: new Date(),
  };

  const result = await equipmentCollection.insertOne(equipment);
  res.send(result);
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
