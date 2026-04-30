import { useState } from "react";

export default function Register() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (!email || !password) {
      alert("All fields required");
      return;
    }

    if (password.length < 8) {
      alert("Password must be 8+ chars");
      return;
    }

    console.log({ email, password }); // later API call
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950">
      <form
        onSubmit={handleSubmit}
        className="bg-gray-900 p-8 rounded-xl w-96"
      >
        <h2 className="text-white text-2xl mb-6">Create Account</h2>

        <input
          type="email"
          placeholder="Email"
          className="w-full mb-4 p-2 bg-gray-800 text-white rounded"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />

        <input
          type="password"
          placeholder="Password"
          className="w-full mb-4 p-2 bg-gray-800 text-white rounded"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <button className="w-full bg-blue-600 py-2 rounded hover:bg-blue-700">
          Register
        </button>
      </form>
    </div>
  );
}