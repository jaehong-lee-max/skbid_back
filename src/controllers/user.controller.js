import pool from "../db.js";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import fetch from "node-fetch";
import twilio from "twilio";
import jwt from "jsonwebtoken";

// 토큰 발급 함수 (헬퍼)
const generateTokens = (user) => {
  const accessToken = jwt.sign(
    { id: user.id, email: user.email_id, role: user.role },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: "15m" }, // 억세스 토큰은 짧게!
  );

  const refreshToken = jwt.sign(
    { id: user.id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "7d" }, // 리프레쉬 토큰은 길게!
  );

  return { accessToken, refreshToken };
};

export const login = async (req, res) => {
  try {
    const { admin_id, password } = req.body;

    const [rows] = await pool.query(
      "SELECT * FROM admin_users WHERE adminId = ?",
      [admin_id],
    );

    const user = rows[0];
    if (!user) {
      return res
        .status(401)
        .json({ message: "이메일 또는 비밀번호가 틀렸습니다." });
    }

    // 비밀번호 체크
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(401)
        .json({ message: "이메일 또는 비밀번호가 틀렸습니다." });
    }

    // 토큰 발급
    const { accessToken, refreshToken } = generateTokens({
      ...user,
      role: "admin",
    });

    res.status(200).json({
      message: "로그인 성공!",
      accessToken,
      refreshToken,
      user: { admin_id: user.adminId, adming_name: user.name },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

export const logoutUser = async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      message: "서버 로그아웃 처리 완료! 클라이언트 토큰을 삭제하세요. 웅..!",
    });
  } catch (err) {
    console.error("Logout Error:", err);
    res
      .status(500)
      .json({ message: "로그아웃 처리 중 서버 오류가 발생했어요." });
  }
};
