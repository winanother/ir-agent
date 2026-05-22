import { Orbitron, Exo_2 } from "next/font/google";
import "./globals.css";

const orbitron = Orbitron({
  variable: "--font-orbitron",
  subsets: ["latin"],
});

const exo2 = Exo_2({
  variable: "--font-exo2",
  subsets: ["latin"],
});

export const metadata = {
  title: "INCIDENT RESPONSE - Cyber Threat Intelligence",
  description: "Advanced Emergency Response Agent & Threat Command Center",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="zh-CN" className={`${orbitron.variable} ${exo2.variable}`}>
      <body className="font-body text-gray-200 antialiased min-h-screen relative selection:bg-neon-blue/30 selection:text-neon-blue">
        {/* CRT Scanline Overlay */}
        <div className="pointer-events-none fixed inset-0 z-[100] h-full w-full bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.1)_50%),linear-gradient(90deg,rgba(255,0,0,0.03),rgba(0,255,0,0.01),rgba(0,0,255,0.03))] bg-[length:100%_4px,3px_100%] opacity-20" />

        {/* Glowing Background Mesh */}
        <div className="pointer-events-none fixed inset-0 z-0 h-full w-full bg-bg-dark">
          <div className="absolute top-[-10%] left-[-10%] h-[40rem] w-[40rem] rounded-full bg-neon-purple/10 blur-[120px]" />
          <div className="absolute bottom-[20%] right-[-10%] h-[30rem] w-[30rem] rounded-full bg-neon-blue/10 blur-[100px]" />
        </div>

        <div className="relative z-10 flex min-h-screen flex-col">
          {children}
        </div>
      </body>
    </html>
  );
}
