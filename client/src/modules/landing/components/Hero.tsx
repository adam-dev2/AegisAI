import { Link } from "react-router-dom";

export default function Hero() {
  return (
    <section className="bg-gray-950 text-white min-h-screen flex items-center justify-center">
      <div className="text-center max-w-3xl">
        <h1 className="text-5xl font-bold mb-6">
          AI That Investigates Security Alerts For You
        </h1>

        <p className="text-gray-400 mb-8">
          Reduce alert fatigue and automate triage with an AI-powered SOC analyst.
        </p>

        <div className="flex gap-4 justify-center">
          <button className="bg-blue-600 px-6 py-3 rounded-lg hover:bg-blue-700">
            Get Started
          </button>

            <Link to="/login">
                    <button className="border border-gray-600 px-6 py-3 rounded-lg hover:bg-gray-800">
                     Login
                    </button>
            </Link>
        </div>
      </div>
    </section>
  );
}