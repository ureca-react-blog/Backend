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

// 비밀번호 해싱을 위한 salt (가져온 값은 문자열이기 때문에 Number객체 사용)
const saltRounds = Number(process.env.BCRYPT_SALT_ROUNDS);

//---------------------------------------------

app.get("/", (req, res) => {
  res.send("Hello World!");
});

// 회원가입 API
app.post("/register", async (req, res) => {
  console.log("------", req.body);
  const { username, password } = req.body;

  try {
    // 1. userModel에서 이미 존재하는 사용자인지 확인하기
    const existingUser = await userModel.findOne({ username });
    // 이미 존재하는 사용자라면 프론트로 상태 응답 메시지 보내기
    if (existingUser)
      return res.status(400).json({ message: "이미 존재하는 사용자입니다" }); // 프론트로 응답 보내기
    // 2. 없으면 새 사용자 생성하기
    const userDoc = new userModel({
      username,
      // 2.1 bcrypt가 제공한 hashSync 함수를 통해 비밀번호 해싱하기
      password: bcrypt.hashSync(password, saltRounds), // 사용자 입력 패스워드 해싱하기 (bcrypt가 제공한 암호 함수를 통해)
    });
    // 2.2 MongoDB에 사용자 정보 저장하기
    const savedUser = await userDoc.save();
    // 3. 저장 성공하면 사용자 정보를 프론트로 보내기
    return res.status(201).json({
      username: savedUser.username,
      _id: savedUser._id,
    });
  } catch (error) {
    console.log("응답 에러", error);
    // 보안적인 이슈로 에러 메시지는 구체적으로 보내지 말기
    return res.status(500).json({ message: "서버 오류가 발생했습니다" });
  }
});

app.listen(port, () => {
  console.log(`${port} 포트에서 돌고 있음`);
});
