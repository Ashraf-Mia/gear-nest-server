import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";
import { createRemoteJWKSet, jwtVerify } from "jose";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

const client = new MongoClient(process.env.MONGODB_URI);

let db;

export async function connectToDatabase() {
  if (db) {
    return db;
  }

  try {
    await client.connect();
    db = client.db("gear-nest");

    await db
      .collection("payments")
      .createIndex({ stripeSessionId: 1 }, { unique: true });

    return db;
  } catch (error) {
    console.error("Error connecting to database:", error);
    // Fail fast: the route handlers cannot work without a database.
    throw error;
  }
}

await connectToDatabase();
const usersCollection = db.collection("user");
const equipmentCollection = db.collection("equipment");
const favoritesCollection = db.collection("favorites");
const paymentsCollection = db.collection("payments");

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

// A customer can favorite an item only once. The unique index also protects
// against two rapid clicks racing each other.
try {
  await favoritesCollection.createIndex(
    { userEmail: 1, equipmentId: 1 },
    { unique: true },
  );
} catch (error) {
  // Do not stop the API if the index already exists with different options or
  // if legacy duplicate rows are present; the toggle route still checks first.
  console.error("Could not create the favorites index:", error);
}

// ---------------------------------------------------------------------------
// Authentication and role middleware
// ---------------------------------------------------------------------------

const AUTH_URL = process.env.AUTH_URL;

if (!AUTH_URL) {
  throw new Error("AUTH_URL is required to verify access tokens.");
}

// Better Auth publishes its JWKS at this URL. createRemoteJWKSet caches the
// keys and refreshes them when needed, so this is safe to create once.
const JWKS = createRemoteJWKSet(new URL(`${AUTH_URL}/api/auth/jwks`));

const verifyJwt = (token) =>
  jwtVerify(token, JWKS, {
    issuer: AUTH_URL,
    audience: AUTH_URL,
  });

const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Unauthorized access" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const { payload } = await verifyJwt(token);
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
    const { payload } = await verifyJwt(token);
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// User input is used inside a RegExp for the search filter. Escaping it stops
// characters like "(" or "*" from throwing "Invalid regular expression".
const escapeRegex = (value) =>
  String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

app.get("/", (req, res) => {
  res.send("Server is running");
});

// ---------------------------------------------------------------------------
// Equipment routes
// ---------------------------------------------------------------------------

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

// Public list. Customers and guests only see approved equipment. This is the
// only list route: it returns { equipment, total, page, totalPages }, which the
// client depends on.
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

    // 1. Only approved equipment is public.
    const query = { status: "approved" };

    // 2. Search by name or location (case-insensitive).
    if (search) {
      const regex = new RegExp(escapeRegex(search), "i");
      query.$or = [{ name: regex }, { location: regex }];
    }

    // 3. Category and rental type filters.
    if (category) query.category = category;
    if (rentalType) query.rentalType = rentalType;

    // 4. Price range. Equipment documents store `rentalPrice`, not `price`.
    //    Invalid numbers are ignored instead of becoming NaN in the query.
    const min = Number(minPrice);
    const max = Number(maxPrice);
    const priceFilter = {};
    if (Number.isFinite(min)) priceFilter.$gte = min;
    if (Number.isFinite(max)) priceFilter.$lte = max;
    if (Object.keys(priceFilter).length > 0) query.rentalPrice = priceFilter;

    // 5. Availability uses `availableQuantity` (the field the forms save).
    if (availability === "available") query.availableQuantity = { $gt: 0 };
    if (availability === "unavailable") query.availableQuantity = { $lte: 0 };

    // 6. Sorting (1 = ascending, -1 = descending).
    let sortOption = { createdAt: -1 };
    if (sort === "price-low") sortOption = { rentalPrice: 1 };
    if (sort === "price-high") sortOption = { rentalPrice: -1 };

    // 7. Pagination.
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
app.get("/equipment/my", verifyToken, verifyOwner, async (req, res) => {
  const result = await equipmentCollection
    .find({ ownerEmail: req.user.email })
    .toArray();

  res.send(result);
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

    if (!["pending", "approved", "rejected"].includes(status)) {
      return res.status(400).send({ message: "Invalid status" });
    }

    const equipmentId = new ObjectId(req.params.id);
    const equipment = await equipmentCollection.findOne({ _id: equipmentId });

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

// Update one equipment item. Only its owner can update it.
app.patch("/equipment/:id", verifyToken, verifyOwner, async (req, res) => {
  try {
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

    const fieldsToUpdate = {};
    if (name !== undefined) fieldsToUpdate.name = name;
    if (category !== undefined) fieldsToUpdate.category = category;

    // Numbers are enforced here too, so an edit cannot turn the price or
    // quantity back into a string.
    if (rentalPrice !== undefined) {
      const value = Number(rentalPrice);
      if (!Number.isFinite(value)) {
        return res
          .status(400)
          .send({ message: "rentalPrice must be a number" });
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
    console.error("Failed to update equipment:", error);
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

// ---------------------------------------------------------------------------
// Favorites routes (customer only)
// ---------------------------------------------------------------------------

// GET /favorites -> approved equipment saved by this customer, newest first.
app.get("/favorites", verifyToken, verifyRenter, async (req, res) => {
  try {
    const favorites = await favoritesCollection
      .find({ userEmail: req.user.email })
      .sort({ createdAt: -1 })
      .toArray();

    if (favorites.length === 0) {
      return res.json([]);
    }

    const equipmentIds = favorites.map((favorite) => favorite.equipmentId);
    const equipment = await equipmentCollection
      .find({ _id: { $in: equipmentIds }, status: "approved" })
      .toArray();

    // The database does not guarantee the same order as the favorites list,
    // so rebuild it and drop items that were deleted or unapproved.
    const equipmentById = new Map(
      equipment.map((item) => [String(item._id), item]),
    );
    const result = favorites
      .map((favorite) => equipmentById.get(String(favorite.equipmentId)))
      .filter(Boolean);

    res.json(result);
  } catch (error) {
    console.error("Failed to load favorites:", error);
    res.status(500).json({ message: "Failed to load favorites" });
  }
});

// GET /favorites/check?equipmentId=... -> used by the details page on load so
// the heart button is correct even after a hard refresh.
app.get("/favorites/check", verifyToken, verifyRenter, async (req, res) => {
  const equipmentId = String(req.query.equipmentId ?? "");

  if (!ObjectId.isValid(equipmentId)) {
    return res.status(400).json({ message: "Invalid equipment id" });
  }

  try {
    const favorite = await favoritesCollection.findOne({
      userEmail: req.user.email,
      equipmentId: new ObjectId(equipmentId),
    });

    res.json({ favorited: Boolean(favorite) });
  } catch (error) {
    console.error("Failed to check favorite:", error);
    res.status(500).json({ message: "Failed to check favorite" });
  }
});

// POST /favorites/toggle { equipmentId } -> add or remove in one call.
// The unique index on { userEmail, equipmentId } prevents duplicates.
app.post("/favorites/toggle", verifyToken, verifyRenter, async (req, res) => {
  const equipmentId = String(req.body?.equipmentId ?? "");

  if (!ObjectId.isValid(equipmentId)) {
    return res.status(400).json({ message: "Invalid equipment id" });
  }

  try {
    const id = new ObjectId(equipmentId);

    // Customers can only favorite approved equipment. The 404 also avoids
    // revealing unapproved listings.
    const equipment = await equipmentCollection.findOne({
      _id: id,
      status: "approved",
    });

    if (!equipment) {
      return res.status(404).json({ message: "Equipment not found" });
    }

    const existing = await favoritesCollection.findOne({
      userEmail: req.user.email,
      equipmentId: id,
    });

    if (existing) {
      await favoritesCollection.deleteOne({ _id: existing._id });
      return res.json({ favorited: false });
    }

    try {
      await favoritesCollection.insertOne({
        userEmail: req.user.email,
        equipmentId: id,
        createdAt: new Date(),
      });
    } catch (error) {
      // 11000 = duplicate key. A second click raced the first insert; the
      // end state the customer wanted is still "favorited", so ignore it.
      if (error?.code !== 11000) throw error;
    }

    res.json({ favorited: true });
  } catch (error) {
    console.error("Failed to toggle favorite:", error);
    res.status(500).json({ message: "Failed to update favorite" });
  }
});

// DELETE /favorites/:equipmentId -> explicit remove used by the dashboard.
// Deleting a missing favorite is still a success (idempotent).
app.delete(
  "/favorites/:equipmentId",
  verifyToken,
  verifyRenter,
  async (req, res) => {
    const { equipmentId } = req.params;

    if (!ObjectId.isValid(equipmentId)) {
      return res.status(400).json({ message: "Invalid equipment id" });
    }

    try {
      await favoritesCollection.deleteOne({
        userEmail: req.user.email,
        equipmentId: new ObjectId(equipmentId),
      });

      res.json({ favorited: false });
    } catch (error) {
      console.error("Failed to remove favorite:", error);
      res.status(500).json({ message: "Failed to remove favorite" });
    }
  },
);

// ---------------------------------------------------------------------------
// Profile and users
// ---------------------------------------------------------------------------

// This returns the profile of the logged-in user.
app.get("/profile", verifyToken, async (req, res) => {
  const user = await usersCollection.findOne({ email: req.user.email });

  res.send(user);
});

// This lets an admin get all users.
app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
  const result = await usersCollection.find().toArray();
  res.send(result);
});

// ---------------------------------------------------------------------------
// 404 and error handling
// ---------------------------------------------------------------------------

// ===== Stripe Webhook (express.json() এর আগে) =====

// Unknown routes return JSON instead of Express's default HTML page, so the
// client never tries to parse HTML as JSON.
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

// Express 5 forwards rejected async handlers here. Log the real error but do
// not leak internals to the client.
app.use((error, req, res, next) => {
  // A malformed JSON body is a client error, not a server failure.
  if (error?.type === "entity.parse.failed") {
    return res.status(400).json({ message: "Invalid JSON body" });
  }

  console.error("Unhandled server error:", error);
  res.status(500).json({ message: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
