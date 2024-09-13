import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";
import ShowComponents from "@/components/ShowComponents/ShowComponents";
import { AuthProvider } from "@/context/AuthContext";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "experimento-tio",
  description: "Generated by create next app",
};

interface RootLayoutProps {
  children: React.ReactNode;
}

export default function RootLayout({ children }: RootLayoutProps) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <AuthProvider>

        <ShowComponents>
        <Navbar />
        </ShowComponents>
        {children}
        <Footer />
        </AuthProvider>
      </body>
    </html>
  );
}
