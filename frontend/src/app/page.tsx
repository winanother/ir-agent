import Navbar from "@/components/Navbar";
import HeroOverview from "@/components/HeroOverview";
import UploadAnalysis from "@/components/UploadAnalysis";
import TaskCarousel from "@/components/TaskCarousel";
import ConfigPanel from "@/components/ConfigPanel";
import Footer from "@/components/Footer";

export default function Home() {
  return (
    <>
      <Navbar />
      <main className="flex-1">
        <HeroOverview />
        <UploadAnalysis />
        <TaskCarousel />
        <ConfigPanel />
      </main>
      <Footer />
    </>
  );
}
