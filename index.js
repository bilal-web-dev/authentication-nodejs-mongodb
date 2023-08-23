import path from "path";
import express from "express";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt"


const app = express();

mongoose
  .connect("mongodb://127.0.0.1:27017/", {
    dbName: "nodejs",
  })
  .then(() => console.log("Database is connected"))
  .catch((e) => console.log(e));

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

const User = mongoose.model("User", userSchema);

//Middlewares
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(express.static(path.join(path.resolve(), "public")));
app.use(cookieParser());

const isAuthenticated = async (req, res, next) => {
  const { token } = req.cookies;

  if (token) {
    const decoded = jwt.verify(token, "secret");

    req.user = await User.findById(decoded._id);

    next();
  } else {
    res.redirect("login");
  }
};

app.get("/", isAuthenticated, (req, res) => {
  const { name } = req.user;
  res.render("logout", { name:name });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  let user = await User.findOne({ email });

  if (user) {
    alert("User Already Present, Please Login");

    res.redirect("/");
    return;
  }

  const hashedPassword = await bcrypt.hash(password, 10)

  user = await User.create({
    name,
    email,
    password:hashedPassword
  });

  res.redirect("/");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    return res.redirect("/register");
    
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
     res.render("login", { message: "Invalid credentials" });
     return;
  }

  const token = await jwt.sign({ _id: user._id }, "secret");

  await res.cookie("token", token, {
    httpOnly: true,
  });

  res.redirect("/");
});



app.listen(4000, () => {
  console.log("Server is working");
});
