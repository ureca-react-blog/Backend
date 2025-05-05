import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { userModel } from "./model/user.js";
import dotenv from "dotenv";
import multer from "multer";
import path from "path"; // node.js 제공 (설치 X)
import fs from "fs"; // node.js 제공 (설치 X)
import { postModel } from "./model/post.js";
import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true, // true로 설정하면 쿠키를 포함한 요청 허용
  })
);
app.use(express.json());
app.use(cookieParser());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

mongoose
  .connect(process.env.MONGODB_URI, { dbName: process.env.MONGODB_DB_NAME })
  .then(() => console.log("MongoDB 연결 성공"))
  .catch(() => {
    console.log("MongoDB 연결 실패");
  }); // mongoDB 연결하기

// 비밀번호 해싱을 위한 salt (가져온 값은 문자열이기 때문에 Number객체 사용)
const saltRounds = Number(process.env.BCRYPT_SALT_ROUNDS);

// JWT
const secretKey = process.env.JWT_SECRET;
const tokenLife = process.env.JWT_EXPIRATION; // 토큰의 유효 기간

const cookiesOption = {
  httpOnly: true, // 자바스크립트에서 접근 불가 처리 (XSS 공격 차단)
  maxAge: 1000 * 60 * 60 * 24, // 쿠키 만료 시간 (1일)
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict", // CSRF 방지
  path: "/",
};

//---------------------------------------------

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.get("/uploads/:filename", (req, res) => {
  const { filename } = req.params;
  res.sendFile(path.join(__dirname, "uploads", filename));
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
      // 토큰화하기 위해 DB에서 payload 가져오기
      const { _id, username } = userDoc;
      const payload = { id: _id, username }; // 토큰화하기 위해 DB에서 payload를 가져온다.
      // 3. 비밀번호가 일치하면 sign 함수로 JWT 토큰 발급하기
      const token = jwt.sign(payload, secretKey, {
        expiresIn: tokenLife, //유효 시간은 문자열로
      });
      res // 4. JWT를 쿠키로 프론트에 저장하기
        .cookie("token", token, {
          // 쿠키에 토큰 등록하기
          cookiesOption, // 쿠키 옵션 설정
        })
        // 프론트 스토어에 저장할 때 사용할 데이터 보내기
        .json({ id: userDoc._id, username });
    }
  } catch (error) {
    res.status(500).json({ error: "서버에 연결할 수 없습니다" });
  }
});

// 회원 정보 조회 API
app.get("/profile", (req, res) => {
  // 1. req.cookies 읽어 토큰 정보 가져오기
  const { token } = req.cookies;
  console.log("쿠키", token);
  if (!token) {
    return res.json({ error: "로그인 필요" });
  }
  // 2. jwt.verify 함수로 토큰 유효성 검사하기
  // jwt.verify(토큰, 비밀키, 콜백함수(에러, 정보))
  jwt.verify(token, secretKey, (err, info) => {
    // 유효하지 않다면 에러 메시지 반환하기
    if (err) {
      return res.json({ error: "로그인 필요" });
      // 3. 유효하면 토큰 내부 사용자 정보 반환하기
    } else {
      res.json(info); //info가 쓰이지 않는다면 메시지만 보내도 상관 X
    }
  });
});

// 로그아웃 API
app.post("/logout", (req, res) => {
  const logoutToken = {
    ...cookiesOption,
    maxAge: 0,
  };
  // 1. token 쿠키를 빈 값 + 만료 시간 0으로 설정하기
  res
    .cookie("token", "", logoutToken)
    // 2. 브라우저가 만료된 쿠키를 자동으로 삭제하기
    .json({ message: "로그아웃 되었습니다" });
});

// 게시글 작성 API

// 업로드할 디렉토리 없으면 자동 생성
const uploadDir = "uploads";
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/"); // null = 에러가 없다는 뜻, 경로명
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname)); // uniqueSuffix + 확장자명
  },
});

const upload = multer({ storage });
app.post("/postWrite", upload.single("files"), async (req, res) => {
  try {
    console.log(req.file); // 업로드된 파일 정보
    console.log(req.body); // 폼 데이터

    const { token } = req.cookies; // 쿠키에서 토큰 가져오기
    if (!token) return res.json({ error: "로그인 필요 " });
    const userInfo = jwt.verify(token, secretKey); // 토큰에서 사용자 정보 추출
    console.log("userInfo", userInfo);

    const { title, summary, content } = req.body;
    const postData = {
      title,
      summary,
      content,
      cover: req.file ? req.file.path : null, // 업로드된 파일 경로
      author: userInfo.username, // 사용자 정보 (토큰 활용)
    };

    await postModel.create(postData);
    console.log("게시글 작성 완료");

    res.json({ message: "게시글 작성 완료" });
  } catch (error) {
    console.log("게시글 작성 에러", error);
    return res.status(500).json({ error: "게시글 작성 실패" });
  }
});

// 게시글 목록 조회 API
app.get("/postList", async (req, res) => {
  try {
    const posts = await postModel.find().sort({ createdAt: -1 }).limit(3); // 등록순으로 3개 포스트만 가져오기
    res.json(posts); // 프론트로 리스트 전달하기
  } catch (error) {
    console.log("게시글 목록 조회 실패", error);
    res.status(500).json({ error: "게시글 목록 조회 실패" }); // 에러 전달하기
  }
});

app.listen(port, () => {
  console.log(`${port} 포트에서 돌고 있음`);
});
