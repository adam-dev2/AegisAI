export default function Login() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950">
      <div className="bg-gray-900 p-8 rounded-xl w-96">
        <h2 className="text-white text-2xl mb-6">Login</h2>

        <input
          type="email"
          placeholder="Email"
          className="w-full mb-4 p-2 bg-gray-800 text-white rounded"
        />

        <input
          type="password"
          placeholder="Password"
          className="w-full mb-4 p-2 bg-gray-800 text-white rounded"
        />

        <button className="w-full bg-blue-600 py-2 rounded hover:bg-blue-700">
          Login
        </button>
      </div>
    </div>
  );
}