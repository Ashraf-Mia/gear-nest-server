import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";
import { createRemoteJWKSet, jwtVerify } from "jose";
import Stripe from "stripe";

dotenv.config();

if (!process.env.STRIPE_SECRET_KEY) {
  throw new Error("STRIPE_SECRET_KEY is missing. Add it to your .env file.");
}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const app = express();
app.use(cors());

app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  handleStripeWebhook,
);

app.use(express.json());

const PORT = process.env.PORT || 5000;

const clientUrl = process.env.CLIENT_URI || "http://localhost:3000";

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

    throw error;
  }
}

await connectToDatabase();
const usersCollection = db.collection("user");
const equipmentCollection = db.collection("equipment");
const favoritesCollection = db.collection("favorites");
const bookingsCollection = db.collection("bookings");
const paymentsCollection = db.collection("payments");

async function getDB() {
  return db;
}

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

try {
  await favoritesCollection.createIndex(
    { userEmail: 1, equipmentId: 1 },
    { unique: true },
  );
} catch (error) {
  console.error("Could not create the favorites index:", error);
}

const AUTH_URL = process.env.AUTH_URL;

if (!AUTH_URL) {
  throw new Error("AUTH_URL is required to verify access tokens.");
}

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

// Equipment can be edited by the owner of the record or by an admin, who may
// moderate any listing. Ownership itself is still checked inside the route.
const verifyOwnerOrAdmin = (req, res, next) => {
  if (req.user.role !== "owner" && req.user.role !== "admin") {
    return res.status(403).send({ message: "Forbidden: Owner or admin only" });
  }
  next();
};

const verifyRenter = (req, res, next) => {
  if (req.user.role !== "customer") {
    return res.status(403).send({ message: "Forbidden: Customer only" });
  }
  next();
};

const escapeRegex = (value) =>
  String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

app.get("/", (req, res) => {
  res.send("Server is running");
});

// Equipment routes

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

// Public six most recent approved equipment for the home page. Guests and customers see the same list.
app.get("/equipment/featured", async (req, res) => {
  const result = await equipmentCollection
    .find({ status: "approved" })
    .sort({ createdAt: -1 })
    .limit(6)
    .toArray();

  res.send(result);
});

// The logged-in owner's equipment.
app.get("/equipment/my", verifyToken, verifyOwner, async (req, res) => {
  const result = await equipmentCollection
    .find({ ownerEmail: req.user.email })
    .toArray();

  res.send(result);
});

// Admin only: all equipment (pending, approved, rejected)
app.get("/admin/equipment", verifyToken, verifyAdmin, async (req, res) => {
  const { status } = req.query;
  const query = status ? { status } : {};

  const result = await equipmentCollection
    .find(query)
    .sort({ createdAt: -1 })
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

// Update one equipment item. Its owner or an admin can update it.
app.patch(
  "/equipment/:id",
  verifyToken,
  verifyOwnerOrAdmin,
  async (req, res) => {
    try {
      if (!ObjectId.isValid(req.params.id)) {
        return res.status(400).send({ message: "Invalid equipment id" });
      }

      const equipmentId = new ObjectId(req.params.id);
      const equipment = await equipmentCollection.findOne({ _id: equipmentId });

      if (!equipment) {
        return res.status(404).send({ message: "Equipment not found" });
      }

      // An owner must not be able to update someone else's equipment, but an
      // admin can moderate any listing.
      if (
        req.user.role !== "admin" &&
        equipment.ownerEmail !== req.user.email
      ) {
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
  },
);

// Delete one equipment item. Its owner or an admin can delete it.
app.delete(
  "/equipment/:id",
  verifyToken,
  verifyOwnerOrAdmin,
  async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).send({ message: "Invalid equipment id" });
    }

    const equipmentId = new ObjectId(req.params.id);
    const equipment = await equipmentCollection.findOne({ _id: equipmentId });

    if (!equipment) {
      return res.status(404).send({ message: "Equipment not found" });
    }

    if (req.user.role !== "admin" && equipment.ownerEmail !== req.user.email) {
      return res
        .status(403)
        .send({ message: "You can only delete your own equipment" });
    }

    await equipmentCollection.deleteOne({ _id: equipmentId });

    res.send({ message: "Equipment deleted" });
  },
);

app.get("/equipment/:id/availability", async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).send({ message: "Invalid equipment id" });
  }

  const startDate = toDayKey(req.query.startDate);
  const endDate = toDayKey(req.query.endDate);

  if (!startDate || !endDate) {
    return res.status(400).send({
      message: "startDate and endDate must be valid dates (YYYY-MM-DD)",
    });
  }

  if (endDate < startDate) {
    return res
      .status(400)
      .send({ message: "End date must be after start date" });
  }

  try {
    const equipment = await equipmentCollection.findOne({
      _id: new ObjectId(req.params.id),
      status: "approved",
    });

    if (!equipment) {
      return res.status(404).send({ message: "Equipment not found" });
    }

    const totalQuantity = Number(equipment.availableQuantity) || 0;
    const bookedQuantity = await getBookedQuantity(
      equipment._id,
      startDate,
      endDate,
    );

    res.json({
      equipmentId: equipment._id.toString(),
      startDate,
      endDate,
      totalQuantity,
      bookedQuantity,

      availableQuantity: Math.max(0, totalQuantity - bookedQuantity),
    });
  } catch (error) {
    console.error("Failed to check availability:", error);
    res.status(500).send({ message: "Could not check availability" });
  }
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

// Favorites routes (customer only)

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

// Profile and users

app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await usersCollection
      .find(
        {},
        {
          projection: {
            name: 1,
            email: 1,
            image: 1,
            role: 1,
            createdAt: 1,
          },
        },
      )
      .sort({ createdAt: -1 })
      .toArray();

    res.send(result);
  } catch (error) {
    console.error("Failed to load users:", error);
    res.status(500).send({ message: "Could not load users" });
  }
});

// Admin only: change a user's role. The last admin cannot be demoted, otherwise
// nobody would be left to approve equipment or manage users.
app.patch("/users/:id/role", verifyToken, verifyAdmin, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).send({ message: "Invalid user id" });
    }

    const { role } = req.body;

    if (!["customer", "owner", "admin"].includes(role)) {
      return res.status(400).send({ message: "Invalid role" });
    }

    const userId = new ObjectId(req.params.id);
    const user = await usersCollection.findOne({ _id: userId });

    if (!user) {
      return res.status(404).send({ message: "User not found" });
    }

    if (user.role === "admin" && role !== "admin") {
      const adminCount = await usersCollection.countDocuments({
        role: "admin",
      });

      if (adminCount <= 1) {
        return res
          .status(400)
          .send({ message: "The last admin cannot be demoted" });
      }
    }

    await usersCollection.updateOne(
      { _id: userId },
      { $set: { role, updatedAt: new Date() } },
    );

    const updatedUser = await usersCollection.findOne(
      { _id: userId },
      {
        projection: {
          name: 1,
          email: 1,
          image: 1,
          role: 1,
          createdAt: 1,
        },
      },
    );

    res.send(updatedUser);
  } catch (error) {
    console.error("Failed to update the user role:", error);
    res.status(500).send({ message: "Could not update the role" });
  }
});

// ===== Stripe Webhook =====
// This function is registered near the top of the file, before
// express.json(), so req.body is still the raw Stripe payload.
async function handleStripeWebhook(req, res) {
  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers["stripe-signature"],
      process.env.STRIPE_WEBHOOK_SECRET,
    );
  } catch (error) {
    console.error("Webhook signature failed:", error.message);
    return res.status(400).send("Webhook signature failed");
  }

  try {
    if (event.type === "checkout.session.completed") {
      await saveBooking(event.data.object);
    }

    res.send({ received: true });
  } catch (error) {
    console.error("Webhook handling failed:", error);
    res.status(500).send("Webhook handling failed");
  }
}

function getUnits(startDate, endDate, rentalType) {
  const days =
    Math.round((new Date(endDate) - new Date(startDate)) / 86400000) + 1;

  const type = String(rentalType).toLowerCase();

  if (type === "weekly") return Math.ceil(days / 7);
  if (type === "monthly") return Math.ceil(days / 30);
  return days;
}

// Bookings store dates as "YYYY-MM-DD" strings, but older or manually created
// records may hold Date objects. Normalising to one day key keeps the overlap
// comparison reliable for both shapes.
function toDayKey(value) {
  if (!value) return null;

  if (value instanceof Date) {
    return Number.isNaN(value.getTime())
      ? null
      : value.toISOString().slice(0, 10);
  }

  const text = String(value).trim();

  // "YYYY-MM-DD" and full ISO timestamps already start with the day.
  if (/^\d{4}-\d{2}-\d{2}/.test(text)) return text.slice(0, 10);

  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime())
    ? null
    : parsed.toISOString().slice(0, 10);
}

// A booking keeps its units reserved until it is cancelled. Unpaid/pending
// records do not hold stock, so they are left out on purpose.
const STOCK_HOLDING_BOOKING_STATUSES = ["confirmed", "active", "completed"];

// Sum the quantities of this equipment's bookings that overlap the requested
// dates. Returns null when the dates are invalid.
async function getBookedQuantity(equipmentId, startDate, endDate) {
  const startKey = toDayKey(startDate);
  const endKey = toDayKey(endDate);

  if (!startKey || !endKey || endKey < startKey) return null;

  const id = String(equipmentId);
  const idFilter = ObjectId.isValid(id) ? [id, new ObjectId(id)] : [id];

  const bookings = await bookingsCollection
    .find({
      equipmentId: { $in: idFilter },
      bookingStatus: { $in: STOCK_HOLDING_BOOKING_STATUSES },
    })
    .project({ quantity: 1, startDate: 1, endDate: 1 })
    .toArray();

  return bookings
    .filter((booking) => {
      const bookingStart = toDayKey(booking.startDate);
      const bookingEnd = toDayKey(booking.endDate);

      // Overlap: existing.start <= requested.end AND existing.end >= requested.start
      return Boolean(
        bookingStart &&
        bookingEnd &&
        bookingStart <= endKey &&
        bookingEnd >= startKey,
      );
    })
    .reduce((sum, booking) => sum + (Number(booking.quantity) || 0), 0);
}

// How many units are actually free for the requested dates: total stock minus
// every booking that overlaps those dates. Returns null for invalid dates.
async function getAvailableQuantity(equipment, startDate, endDate) {
  const booked = await getBookedQuantity(equipment._id, startDate, endDate);

  if (booked === null) return null;

  const total = Number(equipment.availableQuantity);

  return Math.max(0, (Number.isFinite(total) ? total : 0) - booked);
}

async function saveBooking(session) {
  if (session.payment_status !== "paid") return null;

  const database = await getDB();
  const payments = database.collection("payments");
  const m = session.metadata;

  const payment = {
    stripeSessionId: session.id,
    transactionId: session.payment_intent,
    amount: session.amount_total / 100,
    currency: session.currency,
    customerEmail: m.customerEmail,
    paidAt: new Date().toISOString(),
  };

  try {
    await payments.insertOne(payment);
  } catch (error) {
    if (error.code === 11000) {
      return payments.findOne({ stripeSessionId: session.id });
    }
    throw error;
  }

  // Payment can complete minutes after checkout, so another customer may have
  // taken the stock in the meantime. Confirm only when units are still free;
  // otherwise keep the booking pending for manual handling/refund.
  const equipment =
    ObjectId.isValid(String(m.equipmentId)) && equipmentCollection
      ? await equipmentCollection.findOne({
          _id: new ObjectId(m.equipmentId),
        })
      : null;

  const available = equipment
    ? await getAvailableQuantity(equipment, m.startDate, m.endDate)
    : null;

  const hasStock = available !== null && Number(m.quantity) <= available;

  const result = await database.collection("bookings").insertOne({
    equipmentId: m.equipmentId,
    equipmentName: m.equipmentName,
    customerEmail: m.customerEmail,
    customerName: m.customerName,
    ownerEmail: m.ownerEmail,
    startDate: m.startDate,
    endDate: m.endDate,
    quantity: Number(m.quantity),
    totalAmount: payment.amount,
    contact: m.contact,
    address: m.address,
    notes: m.notes,
    paymentStatus: "paid",
    bookingStatus: hasStock ? "confirmed" : "pending",
    // Flags a paid booking that could not be confirmed because the units were
    // sold out by the time the payment completed.
    availabilityIssue: !hasStock,
    createdAt: new Date().toISOString(),
  });

  payment.bookingId = result.insertedId.toString();
  await payments.updateOne(
    { _id: payment._id },
    { $set: { bookingId: payment.bookingId } },
  );

  return payment;
}

// ===== Checkout route =====
app.post("/bookings/checkout", verifyToken, verifyRenter, async (req, res) => {
  try {
    const {
      equipmentId,
      startDate,
      endDate,
      quantity,
      contact,
      address,
      notes,
    } = req.body;
    const qty = Number(quantity);
    const today = new Date().toISOString().slice(0, 10);

    if (!ObjectId.isValid(equipmentId)) {
      return res.status(400).send({ message: "Invalid equipment" });
    }
    if (!startDate || !endDate || !contact || !address) {
      return res
        .status(400)
        .send({ message: "Please fill all required fields" });
    }
    if (!Number.isInteger(qty) || qty < 1) {
      return res.status(400).send({ message: "Quantity must be at least 1" });
    }
    if (startDate < today) {
      return res
        .status(400)
        .send({ message: "Start date cannot be in the past" });
    }
    if (endDate < startDate) {
      return res
        .status(400)
        .send({ message: "End date must be after start date" });
    }

    const database = await getDB();
    const equipment = await database
      .collection("equipment")
      .findOne({ _id: new ObjectId(equipmentId), status: "approved" });

    if (!equipment) {
      return res.status(404).send({ message: "Equipment not found" });
    }

    const available = await getAvailableQuantity(equipment, startDate, endDate);

    if (available === null) {
      return res
        .status(400)
        .send({ message: "Start and end dates must be valid" });
    }

    if (qty > available) {
      return res.status(409).send({
        message: `Only ${available} unit(s) available for these dates`,
      });
    }

    const units = getUnits(startDate, endDate, equipment.rentalType);

    // Equipment stores its price in `rentalPrice`, not `price`.
    // The server calculates the total so the browser cannot change it.
    const unitPrice = Number(equipment.rentalPrice);
    if (!Number.isFinite(unitPrice) || unitPrice <= 0) {
      return res.status(400).send({ message: "Equipment price is invalid" });
    }

    const total = unitPrice * units * qty;

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      customer_email: req.user.email,
      line_items: [
        {
          quantity: 1,
          price_data: {
            currency: "usd",
            unit_amount: Math.round(total * 100),
            product_data: {
              name: `${equipment.name} (${startDate} to ${endDate}) x${qty}`,
            },
          },
        },
      ],
      metadata: {
        equipmentId,
        equipmentName: equipment.name.slice(0, 100),
        ownerEmail: equipment.ownerEmail,
        customerEmail: req.user.email,
        customerName: String(req.user.name || ""),
        startDate,
        endDate,
        quantity: String(qty),
        contact: String(contact).slice(0, 30),
        address: String(address).slice(0, 400),
        notes: String(notes || "").slice(0, 400),
      },
      success_url: `${clientUrl}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${clientUrl}/payment-cancel`,
    });

    res.send({ url: session.url });
  } catch (error) {
    console.log(error);
    res.status(500).send({ message: "Could not start payment" });
  }
});

// ===== Confirm payment route =====
app.post("/payments/confirm", verifyToken, verifyRenter, async (req, res) => {
  try {
    const { sessionId } = req.body;

    // A missing session id would make Stripe throw a confusing error.
    if (!sessionId) {
      return res.status(400).send({ message: "Missing session id" });
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId);

    // A customer must not be able to confirm someone else's payment.
    if (session.metadata.customerEmail !== req.user.email) {
      return res.status(403).send({ message: "Forbidden" });
    }

    if (session.payment_status !== "paid") {
      return res.status(400).send({ message: "Payment not completed" });
    }

    const payment = await saveBooking(session);

    // saveBooking returns null if the session is not paid.
    if (!payment) {
      return res.status(400).send({ message: "Payment not completed" });
    }

    res.send({
      success: true,
      transactionId: payment.transactionId,
      amount: payment.amount,
    });
  } catch (error) {
    console.error("Failed to confirm payment:", error);
    res.status(500).send({ message: "Could not confirm payment" });
  }
});

// ===== Customer's bookings route =====
app.get("/bookings/my", verifyToken, verifyRenter, async (req, res) => {
  try {
    const database = await getDB();

    // ইমেইল আসে যাচাই করা টোকেন থেকে, তাই অন্যের booking দেখা যাবে না
    const result = await database
      .collection("bookings")
      .find({ customerEmail: req.user.email })
      .sort({ createdAt: -1 }) // নতুন booking আগে
      .toArray();

    res.send(result);
  } catch (error) {
    console.log(error);
    res.status(500).send({ message: "Failed to load bookings" });
  }
});

// Admin only: every booking on the platform. Owner names and equipment images
// live on the equipment document, so they are joined in for the dashboard.
app.get("/bookings", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const bookings = await bookingsCollection
      .find()
      .sort({ createdAt: -1 })
      .toArray();

    // `equipmentId` is stored as a string while `equipment._id` is an ObjectId,
    // so the lookup needs an explicit conversion.
    const equipmentIds = [
      ...new Set(
        bookings
          .map((booking) => String(booking.equipmentId || ""))
          .filter((id) => ObjectId.isValid(id)),
      ),
    ];

    const equipment =
      equipmentIds.length > 0
        ? await equipmentCollection
            .find({ _id: { $in: equipmentIds.map((id) => new ObjectId(id)) } })
            .toArray()
        : [];

    const equipmentById = new Map(
      equipment.map((item) => [item._id.toString(), item]),
    );

    const result = bookings.map((booking) => {
      const item = equipmentById.get(String(booking.equipmentId || ""));

      return {
        ...booking,
        ownerName: item?.ownerName ?? "",
        equipmentImage: item?.image ?? "",
      };
    });

    res.send(result);
  } catch (error) {
    console.error("Failed to load bookings:", error);
    res.status(500).send({ message: "Could not load bookings" });
  }
});

// Logged-in user: own profile
app.get("/profile", verifyToken, async (req, res) => {
  const user = await usersCollection.findOne({ email: req.user.email });

  if (!user) {
    return res.status(404).send({ message: "User not found" });
  }

  res.send(user);
});

// Logged-in user: update own profile
app.patch("/profile", verifyToken, async (req, res) => {
  const { name, image, phone, address } = req.body;

  if (!name || name.trim().length < 2) {
    return res
      .status(400)
      .send({ message: "Name must be at least 2 characters" });
  }

  await usersCollection.updateOne(
    { email: req.user.email },
    {
      $set: {
        name: name.trim(),
        image: image || "",
        phone: phone || "",
        address: address || "",
        updatedAt: new Date(),
      },
    },
  );

  const updatedUser = await usersCollection.findOne({ email: req.user.email });
  res.send(updatedUser);
});

// Logged-in owner: own bookings
app.get("/bookings/owner", verifyToken, verifyOwner, async (req, res) => {
  const result = await bookingsCollection
    .find({ ownerEmail: req.user.email })
    .sort({ createdAt: -1 })
    .toArray();

  res.send(result);
});

// Logged-in owner: analytics
app.get("/analytics/owner", verifyToken, verifyOwner, async (req, res) => {
  const ownerEmail = req.user.email;
  const today = new Date().toISOString().slice(0, 10);

  const totalEquipment = await equipmentCollection.countDocuments({
    ownerEmail,
  });
  const approvedEquipment = await equipmentCollection.countDocuments({
    ownerEmail,
    status: "approved",
  });

  const bookings = await bookingsCollection
    .find({ ownerEmail, paymentStatus: "paid" })
    .toArray();

  // const completedRentals = bookings.filter(
  //   (b) => b.bookingStatus === "completed" || b.endDate < today,
  // ).length;

  const totalEarnings = bookings.reduce((sum, b) => sum + b.totalAmount, 0);

  const monthly = [];
  for (let i = 5; i >= 0; i--) {
    const date = new Date();
    date.setDate(1);
    date.setMonth(date.getMonth() - i);

    const key = date.toISOString().slice(0, 7);
    const earnings = bookings
      .filter((b) => b.createdAt.slice(0, 7) === key)
      .reduce((sum, b) => sum + b.totalAmount, 0);

    monthly.push({
      month: date.toLocaleDateString("en-US", { month: "short" }),
      earnings,
    });
  }

  res.send({
    totalEquipment,
    approvedEquipment,
    totalBookings: bookings.length,
    // completedRentals,
    totalEarnings,
    monthlyEarnings: monthly,
  });
});

// Admin only analytics on dashboard
app.get("/analytics/admin", verifyToken, verifyAdmin, async (req, res) => {
  const today = new Date().toISOString().slice(0, 10);

  const totalUsers = await usersCollection.countDocuments();
  const totalEquipment = await equipmentCollection.countDocuments();
  const totalBookings = await bookingsCollection.countDocuments();

  const pendingApprovals = await equipmentCollection.countDocuments({
    status: "pending",
  });

  const revenueResult = await paymentsCollection
    .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
    .toArray();
  const totalRevenue = revenueResult[0]?.total || 0;

  const bookings = await bookingsCollection
    .find({ paymentStatus: "paid" })
    .toArray();

  const completedRentals = bookings.filter(
    (b) => b.bookingStatus === "completed" || b.endDate < today,
  ).length;

  const monthly = [];
  for (let i = 5; i >= 0; i--) {
    const date = new Date();
    date.setDate(1);
    date.setMonth(date.getMonth() - i);

    const key = date.toISOString().slice(0, 7);
    const monthBookings = bookings.filter(
      (b) => b.createdAt.slice(0, 7) === key,
    );

    monthly.push({
      month: date.toLocaleDateString("en-US", { month: "short" }),
      bookings: monthBookings.length,
      revenue: monthBookings.reduce((sum, b) => sum + b.totalAmount, 0),
    });
  }

  res.send({
    totalUsers,
    totalEquipment,
    totalBookings,
    totalRevenue,
    pendingApprovals,
    completedRentals,
    monthlyStats: monthly,
  });
});

// Unknown routes return JSON instead of Express's default HTML page, so the
// client never tries to parse HTML as JSON.
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

// Express 5 forwards rejected async handlers here. Log the real error but do
// not leak internals to the client.
app.use((error, req, res, next) => {
  if (error?.type === "entity.parse.failed") {
    return res.status(400).json({ message: "Invalid JSON body" });
  }

  console.error("Unhandled server error:", error);
  res.status(500).json({ message: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

export default app;
