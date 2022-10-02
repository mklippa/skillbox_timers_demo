require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const nunjucks = require("nunjucks");
const { nanoid } = require("nanoid");
const crypto = require("crypto");
const WebSocket = require("ws");
const { MongoClient, ObjectId } = require("mongodb");
const http = require("http");
const cookie = require("cookie");

const app = express();
app.use(express.static("public"));

const server = http.createServer(app);

const wss = new WebSocket.Server({ clientTracking: false, noServer: true });
const clients = new Map();

const clientPromise = MongoClient.connect(process.env.DB_URI, {
  useUnifiedTopology: true,
  maxPoolSize: 10,
});

const createDbClient = async () => {
  const client = await clientPromise;
  return client.db("users");
};

app.use(async (req, res, next) => {
  try {
    req.db = await createDbClient();
    next();
  } catch (err) {
    next(err);
  }
});

nunjucks.configure("views", {
  autoescape: true,
  express: app,
  tags: {
    blockStart: "[%",
    blockEnd: "%]",
    variableStart: "[[",
    variableEnd: "]]",
    commentStart: "[#",
    commentEnd: "#]",
  },
});

app.set("view engine", "njk");

app.use(express.json());
app.use(express.static("public"));

const hash = (d) => crypto.createHash("sha256").update(d).digest("hex");

const findUserByUsername = async (db, username) => await db.collection("users").findOne({ username });

const findUserBySessionId = async (db, sessionId) => {
  const session = await db.collection("sessions").findOne({ sessionId }, { projection: { userId: 1 } });

  if (!session) {
    return;
  }

  return db.collection("users").findOne({ _id: ObjectId(session.userId) });
};

const createSession = async (db, userId) => {
  const sessionId = nanoid();

  await db.collection("sessions").insertOne({
    userId,
    sessionId,
  });

  return sessionId;
};

const deleteSession = async (db, sessionId) => {
  await db.collection("sessions").deleteOne({ sessionId });
};

const createUser = async (db, username, password) => {
  const existingUser = await db.collection("users").findOne({ username });

  if (existingUser) return null;

  const { insertedId } = await db.collection("users").insertOne({
    username,
    password: hash(password),
  });
  return insertedId.valueOf();
};

const createTimer = async (db, userId, description) => {
  const timer = {
    description,
    start: new Date(),
    userId,
  };
  const { insertedId } = await db.collection("timers").insertOne(timer);
  return insertedId;
};

const stopTimer = async (db, id, userId) => {
  const result = await db
    .collection("timers")
    .findOneAndUpdate({ _id: id, userId }, { $set: { end: new Date() } }, { returnDocument: "after" });
  if (!result.value) {
    return false;
  }

  return true;
};

const fetchAllTimers = async (db, userId) => {
  return (await db.collection("timers").find({ userId }).toArray()).map((t) => new TimerViewModel(t));
};

const fetchActiveTimers = async (db, userId) => {
  return (
    await db
      .collection("timers")
      .find({ $and: [{ userId }, { end: null }] })
      .toArray()
  ).map((t) => new TimerViewModel(t));
};

const sendAllTimersMsg = async (db, userId) => {
  const msg = JSON.stringify({
    type: "all_timers",
    timers: await fetchAllTimers(db, ObjectId(userId)),
  });
  clients.get(userId).send(msg);
};

const sendActiveTimersMsg = async (db, userId) => {
  const msg = JSON.stringify({
    type: "active_timers",
    timers: await fetchActiveTimers(db, ObjectId(userId)),
  });
  clients.get(userId).send(msg);
};

class TimerViewModel {
  constructor(timer) {
    this.id = timer._id;
    this.userId = timer.userId;
    this.description = timer.description;
    this.start = timer.start;
    this.end = timer.end;
    this.isActive = !timer.end;
    if (this.isActive) {
      this.progress = new Date() - this.start;
    } else {
      this.duration = this.end - this.start;
    }
  }

  stop(time = new Date()) {
    delete this.progress;
    this.end = time;
    this.duration = this.end - this.start;
    this.isActive = false;
  }
}

app.use(cookieParser());

const auth = () => async (req, res, next) => {
  const sessionId = req.cookies["sessionId"];
  if (!sessionId) {
    return next();
  }
  const user = await findUserBySessionId(req.db, sessionId);
  req.user = user;
  req.sessionId = sessionId;
  next();
};

app.get("/", auth(), async (req, res) => {
  res.render("index", {
    user: req.user,
    userToken: req.sessionId,
    authError: req.query.authError === "true" ? "Wrong username or password" : req.query.authError,
  });
});

app.post("/api/timers", auth(), async (req, res) => {
  if (!req.user) {
    return res.sendStatus(401);
  }
  const id = await createTimer(req.db, req.user._id, req.body.description);

  await sendAllTimersMsg(req.db, req.user._id.toString());

  res.status(201).send({ id });
});

app.post("/api/timers/:id/stop", auth(), async (req, res) => {
  if (!req.user) {
    return res.sendStatus(401);
  }
  const id = req.params.id;
  if (await stopTimer(req.db, ObjectId(id), req.user._id)) {
    await sendAllTimersMsg(req.db, req.user._id.toString());

    res.sendStatus(204);
  } else {
    res.status(404).send(`Unknown timer ID: ${id}`);
  }
});

app.post("/signup", bodyParser.urlencoded({ extended: false }), async (req, res) => {
  const { username, password } = req.body;
  if (!(await createUser(req.db, username, password))) {
    return res.redirect("/?authError=true");
  }
  const user = await findUserByUsername(req.db, username);
  if (!user || user.password !== hash(password)) {
    return res.redirect("/?authError=true");
  }
  const sessionId = await createSession(req.db, user._id);
  res.cookie("sessionId", sessionId).cookie("userId", user._id.toString()).redirect("/");
});

app.post("/login", bodyParser.urlencoded({ extended: false }), async (req, res) => {
  const { username, password } = req.body;
  const user = await findUserByUsername(req.db, username);

  if (!user || user.password !== hash(password)) {
    return res.redirect("/?authError=true");
  }
  const sessionId = await createSession(req.db, user._id);
  res.cookie("sessionId", sessionId).cookie("userId", user._id.toString()).redirect("/");
});

app.get("/logout", auth(), async (req, res) => {
  if (!req.user) {
    return res.redirect("/");
  }
  await deleteSession(req.db, req.sessionId);
  res.clearCookie("sessionId").redirect("/");
});

server.on("upgrade", (req, socket, head) => {
  const cookies = cookie.parse(req.headers["cookie"]);
  const userId = cookies && cookies["userId"];

  if (!userId) {
    socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
    socket.destroy();
    return;
  }

  req.userId = userId;
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit("connection", ws, req);
  });
});

wss.on("connection", async (ws, req) => {
  const { userId } = req;

  clients.set(userId, ws);

  ws.on("close", () => {
    clients.delete(userId);
  });

  await sendAllTimersMsg(await createDbClient(), userId);
});

setInterval(async () => {
  for (const userId of clients.keys()) {
    await sendActiveTimersMsg(await createDbClient(), userId);
  }
}, 1000);

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  res.status(500).send(err.message);
});

const port = process.env.PORT || 3000;

server.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
