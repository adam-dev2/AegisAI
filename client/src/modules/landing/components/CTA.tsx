import { Link } from "react-router-dom";

export default function CTA() {
  return (
    <section className="bg-gray-900 text-white py-20 text-center">
      <h2 className="text-3xl font-bold mb-4">
        Start Automating Your SOC Today
      </h2>

      <Link to="/register">
      <button className="bg-blue-600 px-6 py-3 rounded-lg hover:bg-blue-700">
        Request Demo
      </button>
      </Link>
    </section>
  );
}