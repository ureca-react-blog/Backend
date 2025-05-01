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

// JWT
const secretKey = process.env.JWT_SECRET;
const tokenLife = process.env.JWT_EXPIRATION; // 토큰의 유효 기간

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

// 로그인 API
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    // 1. DB에 사용자가 있는지 확인하기
    const userDoc = await userModel.findOne({ username });
    // 없다면 회원가입을 하지 않은 상태
    if (!userDoc) {
      return res.status(401).json({ error: "사용자가 존재하지 않습니다" });
    }

    // 2. 사용자가 있다면 사용자가 입력한 비밀번호와 저장된 비밀번호 비교하기
    // bcrypt가 자동으로 암호 해독
    const passOk = bcrypt.compareSync(password, userDoc.password);
    if (!passOk) {
      return res.status(401).json({ error: "비밀번호가 일치하지 않습니다" });
    } else {
      // 토큰화하기 위해 DB에서 paylaod 가져오기
      const { _id, username } = userDoc;
      const payload = { id: _id, username }; // 토큰화하기 위해 DB에서 paylaod를 가져온다.
      // 3. 비밀번호가 일치하면 sign 함수로 JWT 토큰 발급하기
      const token = jwt.sign(payload, secretKey, {
        expiresIn: tokenLife, //유효 시간은 문자열로
      });
      res // 4. JWT를 쿠키로 프론트에 저장하기
        .cookie("token", token, {
          // 쿠키에 토큰 등록하기
          httpOnly: true, // 자바스크립트에서 접근 불가 처리 (XSS 공격 차단)
        })
        // 프론트 스토어에 저장할 때 사용할 데이터 보내기
        .json({ id: userDoc._id, username });
    }
  } catch (error) {
    res.status(500).json({ error: "서버에 연결할 수 없습니다" });
  }
});

app.listen(port, () => {
  console.log(`${port} 포트에서 돌고 있음`);
});
