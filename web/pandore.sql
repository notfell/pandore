-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Mar 04, 2024 at 07:13 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `pandore`
--

-- --------------------------------------------------------

--
-- Table structure for table `invites`
--

CREATE TABLE `invites` (
  `id` int(11) NOT NULL,
  `value` text NOT NULL,
  `used` int(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `payload`
--

CREATE TABLE `payload` (
  `id` int(11) NOT NULL,
  `title` text NOT NULL,
  `shellcode` text NOT NULL,
  `rc4_key` text NOT NULL,
  `process` text NOT NULL,
  `created_by` int(11) NOT NULL,
  `api` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `payload`
--

INSERT INTO `payload` (`id`, `title`, `shellcode`, `rc4_key`, `process`, `created_by`, `api`) VALUES
(1, 'calc', '0x86,0xae,0x53,0xa7,0x93,0xec,0x11,0x8c,0x57,0xd8,0x87,0x81,0x0d,0xe9,0x21,0x33,0x15,0xec,0x9a,0xfe,0x05,0x74,0xe2,0x69,0x5f,0x1c,0xb2,0xae,0xba,0xfb,0x47,0xc5,0x74,0xd5,0x3f,0x5b,0x96,0x83,0x27,0xd9,0x0d,0xb2,0x20,0x6c,0x1c,0xf2,0x10,0xac,0xb0,0xf5,0x18,0x11,0x5a,0x5c,0x96,0x7a,0xb2,0x9b,0xbf,0xa9,0xce,0x9b,0xd1,0x06,0x58,0xa2,0x68,0x34,0x73,0x13,0x09,0xd5,0x01,0xe3,0x52,0x80,0xed,0x88,0xb9,0xa1,0x49,0x37,0xc8,0x42,0x98,0x95,0x23,0xff,0x0c,0x2e,0x6f,0x26,0xc7,0x7f,0x58,0x1b,0x28,0xb1,0x17,0xe4,0x46,0x9f,0x77,0xe6,0xc9,0x7d,0x6a,0xab,0xc9,0x83,0x6f,0x43,0x3b,0x8c,0xea,0xac,0xa2,0x1d,0x3f,0x89,0x68,0x7d,0x30,0x40,0x26,0xe2,0x24,0x87,0x00,0xcb,0x66,0x4b,0x52,0xe0,0x2f,0xbd,0xfc,0x92,0xd9,0x8c,0xab,0x70,0x82,0x60,0x6c,0x1a,0xd3,0x7a,0xbe,0x5d,0x34,0xfc,0xa7,0x5b,0x53,0xff,0xa3,0xb5,0xea,0xa7,0x22,0x92,0x20,0xe7,0x91,0xfd,0xdb,0xa5,0x2a,0x4e,0xe7,0x2f,0xf1,0xe5,0x62,0xb7,0xdc,0x0e,0x4f,0x5f,0xc5,0x22,0x36,0x56,0x3e,0x4d,0x16,0x05,0x3c,0xc7,0x05,0xe1,0x2a,0x93,0xda,0xb9,0x4b,0x85,0xa0,0xc4,0x52,0x93,0xc3,0x14,0x43,0x7e,0xc3,0xf4,0x64,0x11,0xee,0x12,0xe8,0xc6,0x02,0xf4,0x46,0xd7,0x10,0xfc,0x29,0x75,0x6a,0x29,0x3b,0xc4,0x15,0xb3,0xc5,0xaf,0x0e,0x02,0x2f,0x36,0xc7,0x34,0x98,0xbe,0x5e,0x10,0x51,0xea,0xf9,0xa4,0x07,0x47,0xf6,0x55,0x8f,0x99,0xdd,0x1e,0x9b,0x9c,0x67,0x8e,0x95,0x87,0xad,0x4e,0xad,0x44,0x3d,0x59,0x24,0xed,0x74,0xe6,0x00,0xee,0x8a,0x50', '0x2F,0x59,0x21,0x42,0x70,0xB3,0xCC,0xBC,0xE0,0x94,0x61,0x0C,0xAD,0x0F,0x57,0x24,0x3C,0x7F,0x18,0x00,0x14,0x6C,0x65,0xC5,0x91,0x0F,0x29,0x51,0x58,0xE4,0x83,0xE6,0x07,0x41,0x10,0xD8,0xBA,0xF3,0xCE,0x55,0xD8,0xCD,0x6E,0x40,0x4A,0x57,0xF7,0xA4,0xE8,0xA9,0xB6,0x2E,0x77,0x25,0x27,0x63,0x49,0xA6,0x0A,0x3B,0x16,0x87,0xEE,0xE1', 'alg.exe', 1, '6YmG3rowNb6rLmmUqkt9YSebu7VG04FL');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `token` text NOT NULL,
  `public` text NOT NULL,
  `username` text NOT NULL,
  `admin` tinyint(1) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `token`, `public`, `username`, `admin`) VALUES
(1, '$argon2i$v=19$m=65536,t=4,p=1$LjhDbG5JRzJnd2tNTzlBQw$4slvBD9bzsqR4J1FJVBNlkwTpO9ie1kjNbfEn6s8Zrc', 'pa', 'admin', 1);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `invites`
--
ALTER TABLE `invites`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `payload`
--
ALTER TABLE `payload`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `invites`
--
ALTER TABLE `invites`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `payload`
--
ALTER TABLE `payload`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
