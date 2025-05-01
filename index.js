import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB 연결 성공"))
  .catch(() => {
    console.log("MongoDB 연결 실패");
  }); // mongoDB 연결하기

//---------------------------------------------

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  console.log(`${port} 포트에서 돌고 있음`);
});
