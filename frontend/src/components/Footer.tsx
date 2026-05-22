export default function Footer() {
  return (
    <footer className="mt-24 border-t border-neon-blue/20 bg-black/50">
      <div className="mx-auto flex max-w-7xl flex-col items-center gap-4 px-6 py-10 text-center lg:px-10">
        <div className="h-px w-32 bg-gradient-to-r from-transparent via-neon-blue to-transparent" />
        <p className="font-display text-sm uppercase tracking-[0.35em] text-neon-blue/80">
          Emergency Response Agent
        </p>
        <p className="font-body text-sm text-gray-400">
          Powered by AI · Threat Intelligence · Incident Command Interface
        </p>
      </div>
    </footer>
  );
}
