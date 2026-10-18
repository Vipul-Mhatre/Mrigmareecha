import type { Metadata } from "next";
import { Poppins } from "next/font/google";
import "./index.css";

const poppins = Poppins({
  variable: "--font-poppins",
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700", "800"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "Mrigmareecha | AI-Powered Collective Cyber Defense",
  description:
    "Detect carefully. Understand clearly. Defend together. Transforming controlled-deception signals into explainable threat assessments, reviewable defensive rules, and tamper-evident incident evidence.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${poppins.variable} ${poppins.className} dark h-full antialiased`}
    >
      <body className={`${poppins.className} h-full bg-[#030B18] text-[#EAF2FF] overflow-hidden`}>
        {children}
      </body>
    </html>
  );
}
