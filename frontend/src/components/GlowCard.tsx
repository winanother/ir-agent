type GlowCardProps = {
  children: React.ReactNode;
  className?: string;
  color?: "blue" | "purple" | "pink";
};

const colorMap = {
  blue: "border-neon-blue/30 shadow-neon-blue/10 hover:border-neon-blue/60 hover:shadow-neon-blue/20",
  purple: "border-neon-purple/30 shadow-neon-purple/10 hover:border-neon-purple/60 hover:shadow-neon-purple/20",
  pink: "border-neon-pink/30 shadow-neon-pink/10 hover:border-neon-pink/60 hover:shadow-neon-pink/20",
};

export default function GlowCard({ children, className = "", color = "blue" }: GlowCardProps) {
  return (
    <div
      className={`relative overflow-hidden rounded-2xl border bg-white/5 p-6 backdrop-blur-md transition-all duration-300 ${colorMap[color]} ${className}`}
    >
      <div className="relative z-10">{children}</div>
    </div>
  );
}
