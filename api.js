/* ============================================================
   Tic-Tac-Toe backend  |  Made by Fahad Bagwan
   Runs as a Netlify Function. Stores users, sessions and rooms
   in Netlify Blobs. Passwords are hashed with PBKDF2 (never stored
   in plain text).
   ============================================================ */
const { getStore } = require("@netlify/blobs");
const crypto = require("crypto");

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const reply = (statusCode, body) => ({
  statusCode,
  headers: { ...CORS, "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

const USERNAME_RE = /^[a-z0-9_]{3,16}$/;
const SESSION_DAYS = 30;
const CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const LINES = [
  [0, 1, 2], [3, 4, 5], [6, 7, 8],
  [0, 3, 6], [1, 4, 7], [2, 5, 8],
  [0, 4, 8], [2, 4, 6],
];

/* ---------- Password helpers ---------- */
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex");
  return { salt, hash };
}

function checkPassword(password, user) {
  const { hash } = hashPassword(password, user.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(user.hash, "hex"));
}

/* ---------- Game helpers ---------- */
function findWinner(board) {
  for (const [a, b, c] of LINES) {
    if (board[a] && board[a] === board[b] && board[a] === board[c]) {
      return { winner: board[a], line: [a, b, c] };
    }
  }
  if (board.every(Boolean)) return { winner: "draw", line: null };
  return { winner: null, line: null };
}

// What the client is allowed to see about a room
function roomView(room, username) {
  return {
    code: room.code,
    players: room.players,
    board: room.board,
    turn: room.turn,
    winner: room.winner,
    line: room.line,
    mySymbol: room.players.X === username ? "X" : room.players.O === username ? "O" : null,
  };
}

function newCode() {
  let s = "";
  for (let i = 0; i < 5; i++) s += CODE_CHARS[crypto.randomInt(CODE_CHARS.length)];
  return s;
}

/* ---------- Session helpers ---------- */
async function createSession(sessions, username) {
  const token = crypto.randomBytes(32).toString("hex");
  await sessions.setJSON(token, { username, createdAt: Date.now() });
  return token;
}

async function currentUser(event, sessions) {
  const header = event.headers.authorization || event.headers.Authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return null;
  const s = await sessions.get(token, { type: "json" });
  if (!s) return null;
  if (Date.now() - s.createdAt > SESSION_DAYS * 24 * 60 * 60 * 1000) {
    await sessions.delete(token);
    return null;
  }
  return { username: s.username, token };
}

/* ---------- Main handler ---------- */
exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return reply(204, {});
  if (event.httpMethod !== "POST") return reply(405, { error: "Use POST" });

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (e) {
    return reply(400, { error: "Bad request" });
  }

  const users = getStore("users");
  const sessions = getStore("sessions");
  const rooms = getStore("rooms");

  try {
    const me = await currentUser(event, sessions);

    switch (body.action) {

      /* ----- Accounts ----- */
      case "signup": {
        const username = String(body.username || "").trim().toLowerCase();
        const password = String(body.password || "");
        if (!USERNAME_RE.test(username)) {
          return reply(400, { error: "Username must be 3-16 letters, numbers or _" });
        }
        if (password.length < 6) {
          return reply(400, { error: "Password must be at least 6 characters" });
        }
        if (await users.get(username, { type: "json" })) {
          return reply(409, { error: "Username already taken" });
        }
        const { salt, hash } = hashPassword(password);
        await users.setJSON(username, { salt, hash, createdAt: Date.now() });
        const token = await createSession(sessions, username);
        return reply(200, { token, username });
      }

      case "login": {
        const username = String(body.username || "").trim().toLowerCase();
        const password = String(body.password || "");
        const user = await users.get(username, { type: "json" });
        if (!user || !checkPassword(password, user)) {
          return reply(401, { error: "Wrong username or password" });
        }
        const token = await createSession(sessions, username);
        return reply(200, { token, username });
      }

      case "logout": {
        if (me) await sessions.delete(me.token);
        return reply(200, { ok: true });
      }

      case "me": {
        if (!me) return reply(401, { error: "Please log in" });
        return reply(200, { username: me.username });
      }

      /* ----- Online rooms (need login) ----- */
      case "createRoom": {
        if (!me) return reply(401, { error: "Please log in" });
        let code;
        do { code = newCode(); } while (await rooms.get(code, { type: "json" }));
        const room = {
          code,
          players: { X: me.username, O: null },
          board: Array(9).fill(null),
          turn: "X",
          winner: null,
          line: null,
          updatedAt: Date.now(),
        };
        await rooms.setJSON(code, room);
        return reply(200, roomView(room, me.username));
      }

      case "joinRoom": {
        if (!me) return reply(401, { error: "Please log in" });
        const code = String(body.code || "").trim().toUpperCase();
        const room = await rooms.get(code, { type: "json" });
        if (!room) return reply(404, { error: "Room not found. Check the code." });

        const isPlayer = room.players.X === me.username || room.players.O === me.username;
        if (!isPlayer) {
          if (room.players.O) return reply(409, { error: "Room is full" });
          room.players.O = me.username;
          room.updatedAt = Date.now();
          await rooms.setJSON(code, room);
        }
        return reply(200, roomView(room, me.username));
      }

      case "roomState": {
        if (!me) return reply(401, { error: "Please log in" });
        const code = String(body.code || "").trim().toUpperCase();
        const room = await rooms.get(code, { type: "json" });
        if (!room) return reply(404, { error: "Room not found" });
        if (room.players.X !== me.username && room.players.O !== me.username) {
          return reply(403, { error: "You are not in this room" });
        }
        return reply(200, roomView(room, me.username));
      }

      case "move": {
        if (!me) return reply(401, { error: "Please log in" });
        const code = String(body.code || "").trim().toUpperCase();
        const room = await rooms.get(code, { type: "json" });
        if (!room) return reply(404, { error: "Room not found" });

        const symbol = room.players.X === me.username ? "X"
                     : room.players.O === me.username ? "O" : null;
        if (!symbol) return reply(403, { error: "You are not in this room" });
        if (!room.players.O) return reply(400, { error: "Wait for your friend to join" });
        if (room.winner) return reply(400, { error: "Game is over" });
        if (room.turn !== symbol) return reply(400, { error: "Not your turn" });

        const i = Number(body.index);
        if (!Number.isInteger(i) || i < 0 || i > 8 || room.board[i]) {
          return reply(400, { error: "Invalid move" });
        }

        room.board[i] = symbol;
        const result = findWinner(room.board);
        room.winner = result.winner;
        room.line = result.line;
        room.turn = symbol === "X" ? "O" : "X";
        room.updatedAt = Date.now();
        await rooms.setJSON(code, room);
        return reply(200, roomView(room, me.username));
      }

      case "rematch": {
        if (!me) return reply(401, { error: "Please log in" });
        const code = String(body.code || "").trim().toUpperCase();
        const room = await rooms.get(code, { type: "json" });
        if (!room) return reply(404, { error: "Room not found" });
        if (room.players.X !== me.username && room.players.O !== me.username) {
          return reply(403, { error: "You are not in this room" });
        }
        if (!room.winner) return reply(400, { error: "Finish the game first" });
        room.board = Array(9).fill(null);
        room.turn = "X";
        room.winner = null;
        room.line = null;
        room.updatedAt = Date.now();
        await rooms.setJSON(code, room);
        return reply(200, roomView(room, me.username));
      }

      default:
        return reply(400, { error: "Unknown action" });
    }
  } catch (err) {
    console.error(err);
    return reply(500, { error: "Server error. Please try again." });
  }
};
