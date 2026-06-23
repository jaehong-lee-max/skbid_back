import express from "express";
import crypto from "crypto";
import morgan from "morgan";
import cors from "cors";
import usersRouter from "./routes/user.routes.js"; // 예시 라우트
import errorMiddleware from "./middlewares/error.js";
import jwt from "jsonwebtoken";
import verifyToken from "./middlewares/verifyToken.js";
import pool from "./db.js";
import multer from "multer";
import path from "path";
import qs from "querystring";
import axios from "axios";

const app = express();

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const basename = path.basename(file.originalname, ext);
    // 파일명-날짜.확장자 형태로 깔끔하게 저장!
    cb(null, `${basename}-${Date.now()}${ext}`);
  },
});

const upload = multer({ storage: storage });

const tokenReissue = async (req, res) => {
  try {
    const { refreshToken } = req.body; // body로 통일

    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh token missing" });
    }

    jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET,
      async (err, decoded) => {
        if (err) {
          return res.status(401).json({ message: "Invalid refresh token" });
        }

        const { id } = decoded;

        // ✅ admin_users 테이블에서 관리자 확인
        const [rows] = await pool.query(
          `SELECT * FROM admin_users WHERE id = ?`,
          [id],
        );

        const admin = rows[0];
        if (!admin) {
          return res
            .status(404)
            .json({ message: "관리자 사용자를 찾을 수 없습니다." });
        }

        // ✅ Access Token 재발급
        const newAccessToken = jwt.sign(
          {
            id: admin.id,
            role: "admin",
          },
          process.env.JWT_ACCESS_SECRET,
          { expiresIn: "15m" },
        );

        return res.json({
          accessToken: newAccessToken,
        });
      },
    );
  } catch (e) {
    console.error("Token Reissue Error:", e);
    res.status(500).json({ message: "Server error" });
  }
};
// 공통 미들웨어
app.use(cors());
app.use(morgan("dev"));
app.use(express.json()); // JSON Body 파싱
app.use(express.urlencoded({ extended: true }));

// 헬스체크
app.get("/health", (req, res) => {
  res.json({ ok: true, now: new Date().toISOString(), test: "잘 되었음" });
});
app.post("/api/users/token/reissue", tokenReissue);

app.post("/api/script_template", async (req, res) => {
  try {
    const {
      title,
      openning,
      service,
      tempting,
      if_ban,
      added_question,
      ending,
      writer,
    } = req.body;

    if (!title || !title.trim()) {
      return res.status(400).json({
        message: "title은 필수입니다.",
      });
    }

    const [result] = await pool.query(
      `
      INSERT INTO script_template
      (
        title,
        openning,
        service,
        tempting,
        if_ban,
        added_question,
        ending,
        writer
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        title?.trim() || "",
        openning?.trim() || "",
        service?.trim() || "",
        tempting?.trim() || "",
        if_ban?.trim() || "",
        added_question?.trim() || "",
        ending?.trim() || "",
        writer?.trim() || "",
      ],
    );

    const [rows] = await pool.query(
      `
      SELECT
        id,
        title,
        openning,
        service,
        tempting,
        if_ban,
        added_question,
        ending,
        created_at
      FROM script_template
      WHERE id = ?
      `,
      [result.insertId],
    );

    return res.status(201).json({
      message: "스크립트 템플릿이 등록되었습니다.",
      data: rows[0],
    });
  } catch (err) {
    console.error("script_template create error:", err);
    return res.status(500).json({
      message: "스크립트 템플릿 등록 중 오류가 발생했습니다.",
    });
  }
});

app.get("/api/script_template_list", async (req, res) => {
  try {
    const limit = Number(req.query.limit || 10);
    const page = Number(req.query.page || 1);
    const writer = (req.query.writer || "").trim();

    const offset =
      req.query.offset !== undefined
        ? Number(req.query.offset)
        : (page - 1) * limit;

    const title = (req.query.title || "").trim();
    const startDate = (req.query.startDate || "").trim();
    const endDate = (req.query.endDate || "").trim();

    const where = [];
    const params = [];

    if (title) {
      where.push("title LIKE ?");
      params.push(`%${title}%`);
    }
    if (writer) {
      where.push("writer LIKE ?");
      params.push(`%${writer}%`);
    }

    if (startDate) {
      where.push("DATE(created_at) >= ?");
      params.push(startDate);
    }

    if (endDate) {
      where.push("DATE(created_at) <= ?");
      params.push(endDate);
    }

    const whereSQL = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const [rows] = await pool.query(
      `
      SELECT
        id,
        title,
        openning,
        service,
        tempting,
        if_ban,
        added_question,
        ending,
        writer,
        created_at
      FROM script_template
      ${whereSQL}
      ORDER BY id DESC
      LIMIT ? OFFSET ?
      `,
      [...params, limit, offset],
    );

    const [[{ total }]] = await pool.query(
      `
      SELECT COUNT(*) AS total
      FROM script_template
      ${whereSQL}
      `,
      params,
    );

    return res.json({
      total,
      page,
      limit,
      offset,
      totalPages: Math.ceil(total / limit),
      items: rows,
    });
  } catch (err) {
    console.error("script_template list error:", err);
    return res.status(500).json({
      message: "스크립트 템플릿 목록 조회에 실패하였습니다.",
    });
  }
});

app.delete("/api/script_template", async (req, res) => {
  try {
    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({
        message: "삭제할 스크립트를 선택해 주세요.",
      });
    }

    const cleanIds = ids
      .map((id) => Number(id))
      .filter((id) => Number.isInteger(id) && id > 0);

    if (cleanIds.length === 0) {
      return res.status(400).json({
        message: "올바른 스크립트 ID가 없습니다.",
      });
    }

    const placeholders = cleanIds.map(() => "?").join(",");

    const [result] = await pool.query(
      `
      DELETE FROM script_template
      WHERE id IN (${placeholders})
      `,
      cleanIds,
    );

    return res.json({
      message: "선택한 스크립트가 삭제되었습니다.",
      deletedCount: result.affectedRows,
    });
  } catch (err) {
    console.error("script_template delete error:", err);
    return res.status(500).json({
      message: "스크립트 템플릿 삭제 중 오류가 발생했습니다.",
    });
  }
});

app.post("/api/clients_groups", async (req, res) => {
  try {
    const { writer, group_name, payload } = req.body;

    if (!group_name || !group_name.trim()) {
      return res.status(400).json({
        message: "그룹명을 입력해 주세요.",
      });
    }

    if (!Array.isArray(payload) || payload.length === 0) {
      return res.status(400).json({
        message: "업로드할 발신대상 데이터가 없습니다.",
      });
    }

    const cleanPayload = payload.map((item) => ({
      phone: String(item.phone || item["전화번호"] || "").trim(),
      company: String(item.company || item["회사명"] || "").trim(),
      name: String(item.name || item["담당자명"] || "").trim(),
      position: String(item.position || item["직급"] || "").trim(),
    }));

    const validPayload = cleanPayload.filter((item) => item.phone);

    if (validPayload.length === 0) {
      return res.status(400).json({
        message: "전화번호가 있는 데이터가 없습니다.",
      });
    }

    const [result] = await pool.query(
      `
      INSERT INTO clients_groups
      (
        writer,
        members_number,
        payload,
        group_name
      )
      VALUES (?, ?, ?, ?)
      `,
      [
        writer?.trim() || "",
        validPayload.length,
        JSON.stringify(validPayload),
        group_name.trim(),
      ],
    );

    const [rows] = await pool.query(
      `
      SELECT
        id,
        writer,
        created_at,
        members_number,
        payload,
        group_name
      FROM clients_groups
      WHERE id = ?
      `,
      [result.insertId],
    );

    return res.status(201).json({
      message: "발신대상 그룹이 등록되었습니다.",
      data: rows[0],
    });
  } catch (err) {
    console.error("clients_groups create error:", err);
    return res.status(500).json({
      message: "발신대상 그룹 등록 중 오류가 발생했습니다.",
    });
  }
});

app.get("/api/clients_groups_list", async (req, res) => {
  try {
    const limit = Number(req.query.limit || 10);
    const page = Number(req.query.page || 1);

    const offset =
      req.query.offset !== undefined
        ? Number(req.query.offset)
        : (page - 1) * limit;

    const group_name = (req.query.group_name || "").trim();
    const writer = (req.query.writer || "").trim();
    const startDate = (req.query.startDate || "").trim();
    const endDate = (req.query.endDate || "").trim();

    const where = [];
    const params = [];

    if (group_name) {
      where.push("group_name LIKE ?");
      params.push(`%${group_name}%`);
    }

    if (writer) {
      where.push("writer LIKE ?");
      params.push(`%${writer}%`);
    }

    if (startDate) {
      where.push("DATE(created_at) >= ?");
      params.push(startDate);
    }

    if (endDate) {
      where.push("DATE(created_at) <= ?");
      params.push(endDate);
    }

    const whereSQL = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const [rows] = await pool.query(
      `
      SELECT
        id,
        writer,
        created_at,
        members_number,
        payload,
        group_name
      FROM clients_groups
      ${whereSQL}
      ORDER BY id DESC
      LIMIT ? OFFSET ?
      `,
      [...params, limit, offset],
    );

    const [[{ total }]] = await pool.query(
      `
      SELECT COUNT(*) AS total
      FROM clients_groups
      ${whereSQL}
      `,
      params,
    );

    return res.json({
      total,
      page,
      limit,
      offset,
      totalPages: Math.ceil(total / limit),
      items: rows,
    });
  } catch (err) {
    console.error("clients_groups list error:", err);
    return res.status(500).json({
      message: "발신대상 그룹 목록 조회에 실패하였습니다.",
    });
  }
});

app.delete("/api/clients_groups", async (req, res) => {
  try {
    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({
        message: "삭제할 발신대상 그룹을 선택해 주세요.",
      });
    }

    const cleanIds = ids
      .map((id) => Number(id))
      .filter((id) => Number.isInteger(id) && id > 0);

    if (cleanIds.length === 0) {
      return res.status(400).json({
        message: "올바른 그룹 ID가 없습니다.",
      });
    }

    const placeholders = cleanIds.map(() => "?").join(",");

    const [result] = await pool.query(
      `
      DELETE FROM clients_groups
      WHERE id IN (${placeholders})
      `,
      cleanIds,
    );

    return res.json({
      message: "선택한 발신대상 그룹이 삭제되었습니다.",
      deletedCount: result.affectedRows,
    });
  } catch (err) {
    console.error("clients_groups delete error:", err);

    return res.status(500).json({
      message: "발신대상 그룹 삭제 중 오류가 발생했습니다.",
    });
  }
});

// 예시 라우트(원하시는 테이블 라우터로 교체/추가)
app.use("/api/users", usersRouter);

app.use("/uploads", express.static("uploads"));

// 404 핸들러
app.use((req, res, next) => {
  res.status(404).json({ message: "Not Found" });
});

// 에러 핸들러
app.use(errorMiddleware);

export default app;
