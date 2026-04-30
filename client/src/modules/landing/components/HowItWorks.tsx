export default function HowItWorks() {
  const steps = [
    "Connect Rapid7",
    "Alerts Ingested",
    "AI Investigates",
    "Report Generated",
  ];

  return (
    <section className="bg-gray-950 text-white py-20">
      <div className="max-w-4xl mx-auto text-center">
        <h2 className="text-3xl mb-10 font-bold">How It Works</h2>

        <div className="flex flex-col md:flex-row justify-between gap-6">
          {steps.map((step, i) => (
            <div key={i} className="bg-gray-900 p-6 rounded-xl flex-1">
              <p className="text-lg">{step}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}