import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";
// import { router } from "./routes/index.js";
import { createRemoteJWKSet, jwtVerify } from "jose";
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

// verifyToken, verifyAdmin, verifyOwner, verifyRenter
// const { createRemoteJWKSet, jwtVerify } = require("jose");

const JWKS = createRemoteJWKSet(
  new URL(`${process.env.AUTH_URL}/api/auth/jwks`),
);

const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Unauthorized access" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: process.env.AUTH_URL,
      audience: process.env.AUTH_URL,
    });

    req.user = payload;
    next();
  } catch (error) {
    return res.status(401).send({ message: "Invalid or expired token" });
  }
};

// Get the user from an optional token. Used by the public details route:
// guests have no token, logged-in users do.
const getOptionalUser = async (req) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }

  try {
    const token = authHeader.split(" ")[1];
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: process.env.AUTH_URL,
      audience: process.env.AUTH_URL,
    });

    return payload;
  } catch {
    return null;
  }
};

// These middleware functions run after verifyToken, so req.user already
// exists. The role is inside the JWT, so we do not need another database
// query on every request.
const verifyAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).send({ message: "Forbidden: Admin only" });
  }
  next();
};

const verifyOwner = (req, res, next) => {
  if (req.user.role !== "owner") {
    return res.status(403).send({ message: "Forbidden: Owner only" });
  }
  next();
};

const verifyRenter = (req, res, next) => {
  if (req.user.role !== "customer") {
    return res.status(403).send({ message: "Forbidden: Customer only" });
  }
  next();
};

// start server

app.get("/", (req, res) => {
  res.send("Server is running");
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

// Public list. Customers and guests only see approved equipment.
app.get("/equipment", async (req, res) => {
  const result = await equipmentCollection
    .find({ status: "approved" })
    .toArray();

  res.send(result);
});

// The logged-in owner's equipment.
// verifyToken reads the JWT and puts the user's details in req.user.
// verifyOwner makes sure the user has the "owner" role.
app.get("/equipment/my", verifyToken, verifyOwner, async (req, res) => {
  const result = await equipmentCollection
    .find({ ownerEmail: req.user.email })
    .toArray();

  res.send(result);
});

// Update one equipment item. Only its owner can update it.
app.patch("/equipment/:id", verifyToken, verifyOwner, async (req, res) => {
  try {
    // MongoDB ids have a special format. Check it before using it.
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).send({ message: "Invalid equipment id" });
    }

    const equipmentId = new ObjectId(req.params.id);
    const equipment = await equipmentCollection.findOne({ _id: equipmentId });

    if (!equipment) {
      return res.status(404).send({ message: "Equipment not found" });
    }

    // An owner must not be able to update someone else's equipment.
    if (equipment.ownerEmail !== req.user.email) {
      return res
        .status(403)
        .send({ message: "You can only update your own equipment" });
    }

    // Only these fields can be changed from the dashboard.
    const { name, category, rentalPrice, availableQuantity } = req.body;

    // যে ফিল্ডগুলো পাঠানো হয়েছে শুধু সেগুলোই $set অবজেক্টে রাখা হবে
    const fieldsToUpdate = {};
    if (name !== undefined) fieldsToUpdate.name = name;
    if (category !== undefined) fieldsToUpdate.category = category;
    if (rentalPrice !== undefined) fieldsToUpdate.rentalPrice = rentalPrice;
    if (availableQuantity !== undefined) {
      fieldsToUpdate.availableQuantity = availableQuantity;
    }

    if (Object.keys(fieldsToUpdate).length === 0) {
      return res
        .status(400)
        .send({ message: "No valid fields provided to update" });
    }

    await equipmentCollection.updateOne(
      { _id: equipmentId },
      { $set: fieldsToUpdate },
    );

    // Send the saved equipment back so the page can show the new values.
    const updatedEquipment = await equipmentCollection.findOne({
      _id: equipmentId,
    });

    res.send(updatedEquipment);
  } catch (error) {
    res.status(500).send({ message: "Failed to update equipment" });
  }
});

// Delete one equipment item. Only its owner can delete it.
app.delete("/equipment/:id", verifyToken, verifyOwner, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).send({ message: "Invalid equipment id" });
  }

  const equipmentId = new ObjectId(req.params.id);
  const equipment = await equipmentCollection.findOne({ _id: equipmentId });

  if (!equipment) {
    return res.status(404).send({ message: "Equipment not found" });
  }

  // An owner must not be able to delete someone else's equipment.
  if (equipment.ownerEmail !== req.user.email) {
    return res
      .status(403)
      .send({ message: "You can only delete your own equipment" });
  }

  await equipmentCollection.deleteOne({ _id: equipmentId });

  res.send({ message: "Equipment deleted" });
});

// Public details page. Pending or rejected equipment is only visible to its
// owner and admins.
app.get("/equipment/:id", async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).send({ message: "Invalid equipment id" });
  }

  const equipment = await equipmentCollection.findOne({
    _id: new ObjectId(req.params.id),
  });

  if (!equipment) {
    return res.status(404).send({ message: "Equipment not found" });
  }

  if (equipment.status !== "approved") {
    const user = await getOptionalUser(req);
    const isOwner = user && user.email === equipment.ownerEmail;
    const isAdmin = user && user.role === "admin";

    if (!isOwner && !isAdmin) {
      // 404 keeps unapproved equipment hidden from regular users.
      return res.status(404).send({ message: "Equipment not found" });
    }
  }

  res.send(equipment);
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
