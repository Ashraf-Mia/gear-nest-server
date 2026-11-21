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

// User input is used inside a RegExp for the search filter. Escaping it stops
// characters like "(" or "*" from throwing "Invalid regular expression".
const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Older listings stored the price and quantity as strings, and a few used the
// old `price`/`quantity` field names. Range filters and sorting only work on
// numbers, so convert them once at startup. Running this again is harmless.
async function normalizeEquipmentNumbers() {
  const items = await equipmentCollection
    .find({
      $or: [
        { rentalPrice: { $type: "string" } },
        { availableQuantity: { $type: "string" } },
        { rentalPrice: { $exists: false }, price: { $exists: true } },
        { availableQuantity: { $exists: false }, quantity: { $exists: true } },
      ],
    })
    .toArray();

  for (const item of items) {
    const rentalPrice = Number(item.rentalPrice ?? item.price);
    const availableQuantity = Number(item.availableQuantity ?? item.quantity);

    await equipmentCollection.updateOne(
      { _id: item._id },
      {
        $set: {
          rentalPrice: Number.isFinite(rentalPrice) ? rentalPrice : 0,
          availableQuantity: Number.isFinite(availableQuantity)
            ? availableQuantity
            : 0,
        },
      },
    );
  }

  if (items.length > 0) {
    console.log(`Normalized ${items.length} equipment record(s).`);
  }
}

await normalizeEquipmentNumbers();

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
  // Coerce the two numeric fields so a manual API call cannot store strings
  // that would later break price/availability filters and sorting.
  const rentalPrice = Number(req.body.rentalPrice);
  const availableQuantity = Number(req.body.availableQuantity);

  if (!Number.isFinite(rentalPrice) || !Number.isFinite(availableQuantity)) {
    return res.status(400).send({
      message: "rentalPrice and availableQuantity must be numbers",
    });
  }

  const equipment = {
    ...req.body,
    rentalPrice,
    availableQuantity,
    status: "pending",
    createdAt: new Date(),
  };

  const result = await equipmentCollection.insertOne(equipment);
  res.send(result);
});

// Public list. Customers and guests only see approved equipment.
// There used to be a second GET /equipment further down that returned a bare
// array, but Express only runs the first matching route, so the client always
// received an array instead of { equipment, total, page, totalPages } and
// crashed on `data.equipment.length`. This is now the only list route.
app.get("/equipment", async (req, res) => {
  try {
    const {
      search,
      category,
      rentalType,
      minPrice,
      maxPrice,
      availability,
      sort,
      page = "1",
      limit = "9",
    } = req.query;

    // ১. শুধু approved equipment দেখাবে
    const query = { status: "approved" };

    // ২. সার্চ: নাম অথবা লোকেশন (বড়/ছোট হাতের অক্ষর কোনো ব্যাপার না)
    if (search) {
      const regex = new RegExp(escapeRegex(String(search)), "i");
      query.$or = [{ name: regex }, { location: regex }];
    }

    // ৩. ক্যাটাগরি ও রেন্টাল টাইপ ফিল্টার
    if (category) query.category = category;
    if (rentalType) query.rentalType = rentalType;

    // ৪. প্রাইস রেঞ্জ. Equipment documents store `rentalPrice`, not `price`,
    //    so the old `query.price` filter never matched anything. Invalid
    //    numbers are ignored instead of becoming NaN in the Mongo query.
    const min = Number(minPrice);
    const max = Number(maxPrice);
    const priceFilter = {};
    if (Number.isFinite(min)) priceFilter.$gte = min;
    if (Number.isFinite(max)) priceFilter.$lte = max;
    if (Object.keys(priceFilter).length > 0) query.rentalPrice = priceFilter;

    // ৫. Availability. The add/edit forms save `availableQuantity`; the old
    //    `quantity` field is never written, so it is no longer used here.
    if (availability === "available") query.availableQuantity = { $gt: 0 };
    if (availability === "unavailable") query.availableQuantity = { $lte: 0 };

    // ৬. সর্টিং (1 = ছোট থেকে বড়, -1 = বড় থেকে ছোট)
    let sortOption = { createdAt: -1 }; // ডিফল্ট: নতুন আগে
    if (sort === "price-low") sortOption = { rentalPrice: 1 };
    if (sort === "price-high") sortOption = { rentalPrice: -1 };

    // ৭. পেজিনেশন
    const pageNumber = Math.max(Number(page) || 1, 1);
    const limitNumber = Math.max(Number(limit) || 9, 1);
    const skip = (pageNumber - 1) * limitNumber;

    const total = await equipmentCollection.countDocuments(query);
    const equipment = await equipmentCollection
      .find(query)
      .sort(sortOption)
      .skip(skip)
      .limit(limitNumber)
      .toArray();

    res.json({
      equipment,
      total,
      page: pageNumber,
      totalPages: Math.ceil(total / limitNumber),
    });
  } catch (error) {
    console.error("Failed to load equipment:", error);
    res.status(500).json({ message: "Failed to load equipment" });
  }
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
    // Numbers are enforced here as well, so an edit cannot turn the price or
    // quantity back into a string.
    if (rentalPrice !== undefined) {
      const value = Number(rentalPrice);
      if (!Number.isFinite(value)) {
        return res.status(400).send({ message: "rentalPrice must be a number" });
      }
      fieldsToUpdate.rentalPrice = value;
    }
    if (availableQuantity !== undefined) {
      const value = Number(availableQuantity);
      if (!Number.isFinite(value)) {
        return res
          .status(400)
          .send({ message: "availableQuantity must be a number" });
      }
      fieldsToUpdate.availableQuantity = value;
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

// Admin only: approve or reject equipment.
app.patch(
  "/equipment/:id/status",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).send({ message: "Invalid equipment id" });
    }

    const { status } = req.body;

    // Only these three values are allowed.
    if (!["pending", "approved", "rejected"].includes(status)) {
      return res.status(400).send({ message: "Invalid status" });
    }

    const equipmentId = new ObjectId(req.params.id);
    const equipment = await equipmentCollection.findOne({
      _id: equipmentId,
    });

    if (!equipment) {
      return res.status(404).send({ message: "Equipment not found" });
    }

    await equipmentCollection.updateOne(
      { _id: equipmentId },
      { $set: { status } },
    );

    const updatedEquipment = await equipmentCollection.findOne({
      _id: equipmentId,
    });

    res.send(updatedEquipment);
  },
);

// This returns the profile of the logged-in user.
app.get("/profile", verifyToken, async (req, res) => {
  const user = await db.collection("user").findOne({ email: req.user.email });

  res.send(user);
});

// This lets an admin get all users.
app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
  const result = await usersCollection.find().toArray();
  res.send(result);
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
