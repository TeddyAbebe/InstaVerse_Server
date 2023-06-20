import { Jwt } from "jsonwebtoken";
import bcrypt from "bcryptjs";

import User from "../models/user.js";

const signup = async (req, res) => {
  const { username, email, password, confirmPassword } = req.body;

  try {
    const oldUser = await User.findOne({ email });

    if (oldUser) {
      return res.status(400).json({ msg: "Email already exists" });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ msg: "Passwords do not match" });
    }

    const encryptedPassword = await bcrypt.hash(password, 12);

    const newUser = await User.create({
      username,
      email,
      password: encryptedPassword,
    });

    const token = jwt.sign({ email: newUser.email, id: newUser._id }, "1234", {
      expiresIn: "1h",
    });

    res.status(201).json({ result: newUser, token });
  } catch (error) {
    res.status(500).json({ msg: "Something went wrong" });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const oldUser = await User.findOne({ email });

    if (!oldUser) {
      return res.status(400).json({ msg: "User does not exist" });
    }

    const isPasswordValid = await bcrypt.compare(password, oldUser.password);

    if (!isPasswordValid) {
      return res.status(400).json({ msg: "Invalid Password" });
    }

    const token = jwt.sign({ email: oldUser.email, id: oldUser._id }, "1234", {
      expiresIn: "1h",
    });

    res.status(200).json({ result: oldUser, token });
  } catch (error) {
    res.status(500).json({ msg: "Something went wrong" });
  }
};

export { signup, login };
