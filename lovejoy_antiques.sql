-- phpMyAdmin SQL Dump
-- version 5.2.0
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Dec 04, 2024 at 10:30 PM
-- Server version: 10.4.25-MariaDB
-- PHP Version: 8.1.10

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `evaluation_requests`
--

INSERT INTO `evaluation_requests` (`id`, `user_id`, `details`, `preferred_contact`, `photo`, `request_date`) VALUES
(19, 13, 'This is a test', 'email', 'photo_67507c5d1b98b5.29590021.png', '2024-12-04 15:59:25'),
(20, 13, 'This is a test', 'phone', 'photo_67507f0ea555a6.72202268.png', '2024-12-04 16:10:54');

-- --------------------------------------------------------

--
-- Table structure for table `security_questions`
--

CREATE TABLE `security_questions` (
  `id` int(11) NOT NULL,
  `question` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `tokens`
--

INSERT INTO `tokens` (`id`, `user_id`, `token`, `type`, `expires_at`, `created_at`) VALUES
(147, 13, '1de63b7f91970c1bdfe699cff012749470c7c30fed7c83751a23b3de5915a227', 'password_reset', '2024-12-04 18:51:33', '2024-12-04 16:51:33');

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `name`, `email`, `password`, `phone`, `is_admin`, `registered_at`, `is_verified`) VALUES
(2, 'Admin', 'admin_lovejoy@gmail.com', '$2y$10$ImGnvIneaWio9LHNArp7uuQjQJSKehFXX9kgVMCVoa8axcK5mn6Bi', '07712457812', 1, '2024-11-13 14:33:49', 1),
(3, 'Bill Nye', 'billnye123@gmail.com', '$2y$10$SjvObCRtBHo/pu9VZ5DGYeIitydFnMSUMVYb96hFoclX4Oe9y2tCe', '077481659745', 0, '2024-11-13 22:38:52', 1),
(13, 'Owen', 'owenjgibson@gmail.com', '$2y$10$1gs5XRp0Jf9C/O1M2WVyv.kWL4usknplDGuO8zSg9WCXUOQgldFsG', '07712345678', 0, '2024-12-04 15:32:28', 1),
(15, 'Owen', 'owenmancity@gmail.com', '$2y$10$kTxEc9TGc1zD4aE1liCnNO2Q.OP7rVhk86VYh0NmAvdn6AWloOfqu', '0372103271', 0, '2024-12-04 16:37:59', 0);

-- --------------------------------------------------------

--
-- Table structure for table `user_2fa`
--

CREATE TABLE `user_2fa` (
  `id` int(10) UNSIGNED NOT NULL,
  `user_id` int(10) UNSIGNED NOT NULL,
  `code` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
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
(135, 13, '$2y$10$MHa3wrh09U5AAQ4NULkaA.JO/wgvLMKJZ/FNtYR2x1jNMl.48CTXG', '2024-12-04 18:01:48', 0, '2024-12-04 16:51:50', 1, NULL);

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `user_attempts`
--

INSERT INTO `user_attempts` (`id`, `user_id`, `ip_address`, `action_type`, `attempts`, `last_attempt`, `lock_until`) VALUES
(92, 13, NULL, 'verification', 3, '2024-12-04 16:33:07', '2024-12-05 16:33:10'),
(102, 15, NULL, 'verification', 2, '2024-12-04 17:48:19', NULL),
(103, 13, NULL, 'password_reset', 3, '2024-12-04 17:51:33', NULL),
(104, 15, NULL, 'password_reset', 2, '2024-12-04 17:40:30', NULL),
(106, 15, NULL, 'login', 1, '2024-12-04 16:48:07', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `user_security_questions`
--

CREATE TABLE `user_security_questions` (
  `user_id` int(11) NOT NULL,
  `security_question_id` int(11) NOT NULL,
  `security_answer` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `user_security_questions`
--

INSERT INTO `user_security_questions` (`user_id`, `security_question_id`, `security_answer`) VALUES
(13, 4, '$2y$10$efNsrPUDbfrOGzhV.dYr1OAuoD8gmVQmCSZo69wDvtFWxJpf/Tamy'),
(13, 6, '$2y$10$cqZzjLT2cKjNC80gLBmvA.U6XwrL7ozohdETNsRbM5cieMUbvGoQG'),
(13, 8, '$2y$10$Ao4bJ101ppQnNoe/x9xxOOgTIKecrGAfF0pDJI7ZXm.cfbpd/pFG6'),
(15, 4, '$2y$10$l62qkHy/IoMilpGS6nx9..GSXGLp5jVPTsM/BwGSCb8KvdTyJa0GK'),
(15, 6, '$2y$10$FS.3I6Uxpq7wfKRRR2SzUOFby5ggnRRKJ6Gm755WY0akIjqkTMgwu'),
(15, 8, '$2y$10$q3c/jEILvxvEfbuNO0PYwOc/TPXc/tZ6ojYL2icpKjFUCbiUvjTf2');

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
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=21;

--
-- AUTO_INCREMENT for table `security_questions`
--
ALTER TABLE `security_questions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT for table `tokens`
--
ALTER TABLE `tokens`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=148;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=16;

--
-- AUTO_INCREMENT for table `user_2fa`
--
ALTER TABLE `user_2fa`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=136;

--
-- AUTO_INCREMENT for table `user_attempts`
--
ALTER TABLE `user_attempts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=110;

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
