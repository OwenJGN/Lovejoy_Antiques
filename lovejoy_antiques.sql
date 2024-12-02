-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Dec 02, 2024 at 06:03 PM
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
-- Database: `lovejoy_antiques`
--

-- --------------------------------------------------------

--
-- Table structure for table `evaluation_requests`
--

CREATE TABLE `evaluation_requests` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `details` text NOT NULL,
  `preferred_contact` enum('phone','email') NOT NULL,
  `photo` varchar(255) DEFAULT NULL,
  `request_date` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `evaluation_requests`
--

INSERT INTO `evaluation_requests` (`id`, `user_id`, `details`, `preferred_contact`, `photo`, `request_date`) VALUES
(11, 2, 'Test', 'phone', 'photo_6748e250b65040.86305455.png', '2024-11-28 21:36:16');

-- --------------------------------------------------------

--
-- Table structure for table `security_questions`
--

CREATE TABLE `security_questions` (
  `id` int(11) NOT NULL,
  `question` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `security_questions`
--

INSERT INTO `security_questions` (`id`, `question`) VALUES
(1, 'What was the name of your first pet?'),
(2, 'What is your mother’s maiden name?'),
(3, 'What was the name of your elementary school?'),
(4, 'In what city were you born?'),
(5, 'What is your favorite food?'),
(6, 'What is the name of your favorite book?'),
(7, 'What was your childhood nickname?'),
(8, 'What is the name of the street you grew up on?'),
(9, 'What was the make of your first car?'),
(10, 'What is your favorite movie?');

-- --------------------------------------------------------

--
-- Table structure for table `tokens`
--

CREATE TABLE `tokens` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `token` varchar(255) NOT NULL,
  `type` enum('verification','password_reset') NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `tokens`
--

INSERT INTO `tokens` (`id`, `user_id`, `token`, `type`, `expires_at`, `created_at`) VALUES
(71, 3, 'dd95a5e5c481e57fc04330eebfda5fb9', '', '2024-11-14 23:38:52', '2024-11-13 22:38:52'),
(86, 9, '71782cd82e265bcca8611f4ed3997b4b', 'verification', '2024-11-23 02:35:13', '2024-11-22 01:35:13'),
(114, 11, '927ae2a16e557708942c42db19f00c19', 'verification', '2024-11-29 15:24:21', '2024-11-28 14:24:21'),
(118, 10, '7845f18933252254af0339af6e9e992df1f996ba6c293894b44bbf86700a1eb4', 'password_reset', '2024-11-28 20:37:10', '2024-11-28 18:37:10');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `phone` varchar(20) NOT NULL,
  `is_admin` tinyint(1) DEFAULT 0,
  `registered_at` datetime DEFAULT current_timestamp(),
  `is_verified` tinyint(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `name`, `email`, `password`, `phone`, `is_admin`, `registered_at`, `is_verified`) VALUES
(2, 'Admin', 'admin_lovejoy@gmail.com', '$2y$10$ImGnvIneaWio9LHNArp7uuQjQJSKehFXX9kgVMCVoa8axcK5mn6Bi', '07712457812', 1, '2024-11-13 14:33:49', 1),
(3, 'Bill Nye', 'billnye123@gmail.com', '$2y$10$SjvObCRtBHo/pu9VZ5DGYeIitydFnMSUMVYb96hFoclX4Oe9y2tCe', '077481659745', 0, '2024-11-13 22:38:52', 1),
(9, 'Owen Gibson', 'owenjgibsn@gmail.com', '$2y$10$iHfDlJPQzu2K8BfXgOEt1eb7.btIrLWuCU63mjD23V2jDoIw9153e', '07762748219', 0, '2024-11-22 01:35:13', 0),
(10, 'Owen Gibson', 'owenjgibson@gmail.com', '$2y$10$LxFNd1h9/gV7r.HPV0fxUeIOUvvUx/tJBk9JKdLvhGYh/YjdP.9U.', '07762748219', 0, '2024-11-22 02:28:48', 1),
(11, 'Owen Gibson', 'owenmancity@gmail.com', '$2y$10$D6QeF0gYyTAfSk.YDGiFfOwYB39MlUKpQF7NbKD0aTYFKVXuf5ASC', '07762748220', 0, '2024-11-28 14:21:57', 0);

-- --------------------------------------------------------

--
-- Table structure for table `user_2fa`
--

CREATE TABLE `user_2fa` (
  `id` int(10) UNSIGNED NOT NULL,
  `user_id` int(10) UNSIGNED NOT NULL,
  `code` varchar(6) NOT NULL,
  `expires_at` datetime NOT NULL,
  `attempts` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `last_resend` datetime NOT NULL,
  `resend_count` int(10) NOT NULL DEFAULT 0,
  `lock_until` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `user_2fa`
--

INSERT INTO `user_2fa` (`id`, `user_id`, `code`, `expires_at`, `attempts`, `last_resend`, `resend_count`, `lock_until`) VALUES
(107, 10, '976997', '2024-11-28 20:14:31', 0, '2024-11-28 19:04:34', 4, NULL),
(111, 2, '159382', '2024-11-29 00:24:09', 0, '0000-00-00 00:00:00', 0, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `user_attempts`
--

CREATE TABLE `user_attempts` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `action_type` enum('login','verification','password_reset') NOT NULL,
  `attempts` int(11) NOT NULL DEFAULT 0,
  `last_attempt` datetime DEFAULT NULL,
  `lock_until` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `user_attempts`
--

INSERT INTO `user_attempts` (`id`, `user_id`, `ip_address`, `action_type`, `attempts`, `last_attempt`, `lock_until`) VALUES
(33, 9, NULL, 'login', 2, '2024-11-22 01:37:49', NULL),
(58, 10, NULL, 'password_reset', 3, '2024-11-28 19:37:10', '2024-11-29 20:07:40'),
(60, 11, NULL, 'verification', 3, '2024-11-28 15:24:21', '2024-11-29 15:24:47'),
(78, 10, NULL, 'login', 4, '2024-11-28 20:12:28', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `user_security_questions`
--

CREATE TABLE `user_security_questions` (
  `user_id` int(11) NOT NULL,
  `security_question_id` int(11) NOT NULL,
  `security_answer` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `user_security_questions`
--

INSERT INTO `user_security_questions` (`user_id`, `security_question_id`, `security_answer`) VALUES
(9, 4, '$2y$10$CCqVelo4JNB56.K96DMqbO.NUIcbj5Kzkt1pbzQ2QXzbCQLa7Gpkm'),
(9, 5, '$2y$10$UJ.h.rLzeYO7jqHQoXeZqu1pRnRHN03NuiJ5PrKG4Ka6HRJstGQ4K'),
(9, 6, '$2y$10$n0edtYzL0uV1QLO1FF50IOgnmCE24W72icm6O9yttkdey4on/.8Di'),
(10, 1, '$2y$10$Fd/nW3UV9/eEB0V1khR0je7lranZ8VDtkYFdF3mGBer7qktqF7KSe'),
(10, 4, '$2y$10$XcJMtWDo7sE.J9fF0gwIJewf1yQcltPYVGsjpK000IATil.r6zqfy'),
(10, 8, '$2y$10$dNXVnSTzzCpqqS46lWzZaOsXn6a5pur7Lc9bCcbw7/ZeIafCaVsgK'),
(11, 1, '$2y$10$whG./O.iGf6XDyrpuOJHO.RBJ1UThUogiPxg3jCAe/nlr0nCW9M7q'),
(11, 3, '$2y$10$BabAZ21jxHoyiYUCDXl/8u7RmwEcqc2LznnBqJ3RKu48R8IOUZdLa'),
(11, 7, '$2y$10$H3HaQDlP5WwBn2VUxdeC2eMWzqUpU10Cducy4HcgNGPNHSXFRSNgq');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `evaluation_requests`
--
ALTER TABLE `evaluation_requests`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `security_questions`
--
ALTER TABLE `security_questions`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `tokens`
--
ALTER TABLE `tokens`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `token` (`token`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- Indexes for table `user_2fa`
--
ALTER TABLE `user_2fa`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_id` (`user_id`),
  ADD KEY `idx_code` (`code`);

--
-- Indexes for table `user_attempts`
--
ALTER TABLE `user_attempts`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_user_action` (`user_id`,`action_type`),
  ADD KEY `ip_addresses` (`id`);

--
-- Indexes for table `user_security_questions`
--
ALTER TABLE `user_security_questions`
  ADD PRIMARY KEY (`user_id`,`security_question_id`),
  ADD KEY `security_question_id` (`security_question_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `evaluation_requests`
--
ALTER TABLE `evaluation_requests`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

--
-- AUTO_INCREMENT for table `security_questions`
--
ALTER TABLE `security_questions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT for table `tokens`
--
ALTER TABLE `tokens`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=127;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=20;

--
-- AUTO_INCREMENT for table `user_2fa`
--
ALTER TABLE `user_2fa`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=112;

--
-- AUTO_INCREMENT for table `user_attempts`
--
ALTER TABLE `user_attempts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=79;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `evaluation_requests`
--
ALTER TABLE `evaluation_requests`
  ADD CONSTRAINT `evaluation_requests_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `tokens`
--
ALTER TABLE `tokens`
  ADD CONSTRAINT `tokens_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `user_attempts`
--
ALTER TABLE `user_attempts`
  ADD CONSTRAINT `user_attempts_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `user_security_questions`
--
ALTER TABLE `user_security_questions`
  ADD CONSTRAINT `user_security_questions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `user_security_questions_ibfk_2` FOREIGN KEY (`security_question_id`) REFERENCES `security_questions` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
