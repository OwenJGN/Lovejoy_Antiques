-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Nov 19, 2024 at 06:31 PM
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
  `type` enum('email_verification','password_reset') NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `tokens`
--

INSERT INTO `tokens` (`id`, `user_id`, `token`, `type`, `expires_at`, `created_at`) VALUES
(71, 3, 'dd95a5e5c481e57fc04330eebfda5fb9', 'email_verification', '2024-11-14 23:38:52', '2024-11-13 22:38:52');

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
(7, 'Owen', 'owenjgibson@gmail.com', '$2y$10$2QLc/a/BPnr6tYTxy1keYu5EQsjtksQRetyB44m7v7Zjm83wuNgP2', '07762748220', 0, '2024-11-19 17:17:02', 1);

-- --------------------------------------------------------

--
-- Table structure for table `user_attempts`
--

CREATE TABLE `user_attempts` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `action_type` enum('login','verification') NOT NULL,
  `attempts` int(11) NOT NULL DEFAULT 0,
  `last_attempt` datetime DEFAULT NULL,
  `lock_until` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

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
(7, 1, '$2y$10$uNRwwsiExncivRkDuARH2eJeQjjif/23NyZYIGHhB4fgvqbv7Wp4a'),
(7, 4, '$2y$10$fumBeHUUTf9ib.0ZwSh3meULjuEBY57otK6KfK87CaUqZ0sLCr/LK'),
(7, 8, '$2y$10$8L5sujrKoRVTlfN2DNpZoOjMhumiKO2gCqt8nwTo7TnBtRbmCgFbW');

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
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `security_questions`
--
ALTER TABLE `security_questions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT for table `tokens`
--
ALTER TABLE `tokens`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=78;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- AUTO_INCREMENT for table `user_attempts`
--
ALTER TABLE `user_attempts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=25;

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
