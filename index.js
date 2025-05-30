import express from "express";
import pg from "pg";
import cors from "cors";
import bcrypt from "bcrypt";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

const app = express();
const port = 5000;
const saltRounds = 10;
const JWT_SECRET =
  process.env.JWT_SECRET ||
  "sKj9eFv6HrM3#Lq2vP@wTuKz8WxJfTgXzLm4cBzFv1Q!xShD5V2Tb7z*9K7UoYn";

app.use(cors());
app.use(express.json());
dotenv.config();

const db = new pg.Client({
  user: process.env.DATABASE_USER,
  host: process.env.DATABASE_HOST,
  database: process.env.DATABASE_NAME,
  password: process.env.DATABASE_PASS,
  port: process.env.DATABASE_PORT,
  ssl: true,
});

async function connectToDb() {
  try {
    await db.connect();
    console.log("Connected to Render PostgreSQL 🎉");
  } catch (err) {
    console.error("Error connecting to database:", err);
  }
}

connectToDb();

app.get("/", (req, res) => {
  res.send("Projects Backend");
});

app.post("/register", (req, res) => {
  const { id, username, password } = req.body;

  if (id || !username || !password) {
    return res
      .status(400)
      .json({ error: "Missing required fields (id, username, password)" });
  }
  const randomGeneratedId = uuidv4();
  //hashing password for better security
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.log("Error hashing password");
    } else {
      // Use parameterized query to prevent SQL injection
      const query =
        "INSERT INTO users (id, username, password) VALUES ($1, $2, $3)";

      db.query(query, [randomGeneratedId, username, hash], (err, result) => {
        if (err) {
          console.error("Error executing query", err.stack);
          return res
            .status(500)
            .json({ error: `Error posting data: ${err.message}` });
        }

        res.status(201).json({ message: "Registration Successful" });
      });
    }
  });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await db.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(password, storedHashedPassword, (err, result) => {
        if (err) {
          console.error("Error comparing passwords:", err);
        } else {
          if (result) {
            const token = jwt.sign(
              { userId: user.id, username: user.username },
              JWT_SECRET,
              { expiresIn: "168h" }
            );
            res.json({ message: "Login successful", token });
            // res.send("Login Successful");
          } else {
            res.status(400).json({ message: "Incorrect Password" });
          }
        }
      });
    } else {
      res.status(400).json({ message: "Error finding User" });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/addProject", (req, res) => {
  let { title, description, imageurl, githuburl, livelink } = req.body;
  const id = uuidv4();
  if (imageurl == undefined) {
    imageurl =
      "https://upload.wikimedia.org/wikipedia/commons/thumb/d/d1/Image_not_available.png/800px-Image_not_available.png?20210219185637";
  }
  if (livelink == undefined) {
    livelink = "not defined";
  }
  const query =
    "INSERT INTO project (id, title, description, imageurl, githuburl, livelink) VALUES ($1, $2, $3, $4, $5, $6)";

  db.query(
    query,
    [id, title, description, imageurl, githuburl, livelink],
    (err, result) => {
      if (err) {
        console.error("Error executing query", err.stack);
        return res
          .status(500)
          .json({ error: `Error posting data: ${err.message}` });
      }

      res.status(201).json({ message: "Project Insertion Successful" });
    }
  );
});

app.get("/projects", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM project");
    res.status(200).json(result.rows);
  } catch (err) {
    console.error("Error querying database:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
