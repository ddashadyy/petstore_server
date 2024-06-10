const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const prisma = new PrismaClient();
const uuid = require("uuid");

const generateJWT = (id) => {
  return jwt.sign({ id }, process.env.SECRET_KEY, { expiresIn: "24h" });
};

class UserController {
  async registration(req, res) {
    const { email, password, username, role } = req.body;
    const candidate = await prisma.user.findUnique({
      where: {
        email: email,
      },
    });
    if (candidate) {
      return res.json({
        message: "Пользователь с таким E-mail уже существует",
      });
    } else {
      const hashPassword = await bcrypt.hash(password, 6);
      const user = await prisma.user.create({
        data: {
          username: username,
          email: email,
          password: hashPassword,
          role: role
        },
      });
      const token = generateJWT(user.id, user.email);

      res.json({ message: "success", token: token });
    }
  }

  async login(req, res) {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({
      where: {
        email: email,
      },
    });

    if (user) {
      const comparePassword = bcrypt.compareSync(password, user.password);
      if (comparePassword) {
        const token = generateJWT(user.id, user.email);
        res.json({ message: "success", token: token });
      } else {
        return res.json({ message: "Неверный пароль" });
      }
    } else {
      return res.json({ message: "Пользователя с таким E-mail не существует" });
    }
  }

  async verify(req, res) {
    try {
      const token = req.body.token;
      const claims = jwt.verify(token, process.env.SECRET_KEY);

      if (!claims) {
        return res.status(401).send({ message: "Неавторизирован" });
      }

      const user = await prisma.user.findUnique({
        where: { id: claims.id },
      });

      res.send({ user, token });
    } catch (e) {
      return res.status(401).send({ message: "Неавторизирован" });
    }
  }

  async logout(req, res) {
    res.json({ message: "success", token: "" });
  }
}

module.exports = new UserController();