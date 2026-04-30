export default function Features() {
  const features = [
    {
      title: "Automated Alert Triage",
      desc: "AI analyzes alerts instantly and filters noise.",
    },
    {
      title: "Deep Investigation",
      desc: "Correlates logs and enriches with context.",
    },
    {
      title: "Report Generation",
      desc: "Structured triage reports generated automatically.",
    },
  ];

  return (
    <section className="bg-gray-950 text-white py-20">
      <div className="max-w-6xl mx-auto grid md:grid-cols-3 gap-6">
        {features.map((f, i) => (
          <div key={i} className="bg-gray-900 p-6 rounded-xl">
            <h3 className="text-xl font-semibold mb-2">{f.title}</h3>
            <p className="text-gray-400">{f.desc}</p>
          </div>
        ))}
      </div>
    </section>
  );
}